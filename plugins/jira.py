
from __future__ import print_function
from __future__ import unicode_literals

from rtmbot.core import Plugin
import re
import jira
import logging
from collections import defaultdict
import os

LOGGER = logging.getLogger(__name__)
LOGGER.setLevel(logging.DEBUG)

ISSUE_RE = re.compile(r"[A-Z]{2,}-\d+")

NOREPEAT = 20

class JiraPlugin(Plugin):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        ld = self.slack_client.server.login_data
        self.userid = ld["self"]["id"]
        LOGGER.debug("I am %s", self.userid)
        self.chans = {}
        for chan in ld["channels"]:
            d = {
                "name": chan["name"]
            }

            try:
                d["latest_ts"] = chan["latest"]["ts"]
            except KeyError:
                d["latest_ts"] = "0"

            self.chans[chan["id"]] = d
        jira_user = os.environ.get('JIRA_USER')
        jira_pass = os.environ.get('JIRA_PASSWORD')
        if jira_user is None or jira_pass is None:
            sys.exit("JIRA_USER or JIRA_PASSWORD is not set")
        self.jira = jira.JIRA("https://issues.citrite.net", basic_auth=(jira_user, jira_pass))
        self.chanissues=defaultdict(int)
        self.chanmsgs=defaultdict(int)

    def get_issue(self, issue):
        LOGGER.debug("Trying to get issue %s", issue)
        i = self.jira.issue(issue)
        data = {
            'url': 'N/A',
            'issue': issue,
            'description': 'N/A',
            'status': 'N/A',
            'summary': 'N/A',
            'priority': 'N/A',
            'priority_iconurl': 'N/A',
            'issuetype': 'N/A',
            'issuetype_iconurl': 'N/A',
            'creator': 'N/A',
            'assignee': 'N/A'
        }

        try:
            data['url'] = i.permalink()
        except:
            pass

        try:
            data['description'] = i.fields.description
        except:
            pass

        try:
            data['status'] = i.fields.status.name
        except:
            pass

        try:
            data['summary'] = i.fields.summary
        except:
            pass

        try:
            data['priority'] = i.fields.priority.name
        except:
            pass

        try:
            data['priority_iconurl'] = i.fields.priority.iconUrl
        except:
            pass

        try:
            data['issuetype'] = i.fields.issuetype.name
        except:
            pass

        try:
            data['issuetype_iconurl'] = i.fields.issuetype.iconUrl
        except:
            pass

        try:
            data['creator'] = i.fields.creator.displayName
        except:
            pass

        try:
            data['assignee'] = i.fields.assignee.displayName
        except:
            pass


        return data
        #except jira.exceptions.JIRAERROR:
        #    pass

    def process_message(self, data):
        try:
            LOGGER.debug("Received message %s", data)
            channel_id = data["channel"]

            self.slack_client.api_call("mpim.mark",
                                       channel=channel_id,
                                       ts=data["ts"])

            if data['user'] == self.userid:
                LOGGER.debug("Ignoring message from myself")
                return

            if channel_id.startswith("D"):
                if data["type"] == "message":
                    text = data["text"]
                else:
                    text = None
                # Direct message
                if text == "ping":
                    LOGGER.debug("sending pong")
                    self.slack_client.api_call("chat.postMessage",
                                               channel=channel_id,
                                               as_user=True,
                                               text="PONG")
                    return
                if text == "debug on":
                    LOGGER.setLevel(logging.DEBUG)
                    LOGGER.debug("turning debug on")
                    self.slack_client.api_call("chat.postMessage",
                                               channel=channel_id,
                                               as_user=True,
                                               text="Debug is now on")
                    return
                if text == "debug off":
                    LOGGER.debug("turning debug off")
                    LOGGER.setLevel(logging.INFO)
                    self.slack_client.api_call("chat.postMessage",
                                               channel=channel_id,
                                               as_user=True,
                                               text="Debug is now off")
                    return
                self.slack_client.api_call("chat.postMessage",
                                           channel=channel_id,
                                           as_user=True,
                                           text="huh?")
                return

            if not channel_id in self.chans:
                self.chans[channel_id] = {
                    "name": "somethingnew, need to fetch :-)",
                    "latest_ts": '0'
                }

            channel = self.chans[channel_id]
            channel_name = channel["name"]
            LOGGER.debug("Channel: %s", channel_name)
#            if channel_id != 'C58SGNMEK':
#                print("Ignoring channel {}".format(channel_name))
#                return
            if data['ts'] <= channel["latest_ts"]:
                LOGGER.debug("Ignoring old message")
                return

            self.chanmsgs[channel_name] += 1

            LOGGER.debug("Searching for issue patterns")
            m = ISSUE_RE.findall(data['text'])
            for issue in m:
                LOGGER.debug("Found issue id=%s", issue)
                lastseen = self.chanissues["%s::%s" % (channel_name, issue)]
                curr = self.chanmsgs[channel_name]
                if lastseen != 0 and curr - lastseen < NOREPEAT:
                    LOGGER.debug("Channel %s issue %s recently seen, skipping, curr=%s lastseen=%s" % (
                        channel_name, issue, curr, lastseen))
                    continue

                self.chanissues["%s::%s" % (channel_name, issue)] = curr

                idata = self.get_issue(issue)
                if idata:
                    att = [
                            {
                                "text": idata["description"],
                                "fields": [
                                    {
                                        "title": "Status",
                                        "value": idata["status"],
                                        "short": True
                                    },
                                    {
                                        "title": "Priority",
                                        "value": idata["priority"],
                                        "short": True
                                    },
                                    {
                                        "title": "Created by",
                                        "value": idata["creator"],
                                        "short": True
                                    },
                                    {
                                        "title": "Assigned to",
                                        "value": idata["assignee"],
                                        "short": True
                                    }
                                ],
                            }
                        ]
                    LOGGER.debug("Sending message with issue data")
                    self.slack_client.api_call("chat.postMessage",
                                               channel=channel_id,
                                               as_user=True,
                                               text="<{}|{}> {}".format(idata['url'], issue, idata["summary"]),
                                               attachments=att)
            LOGGER.debug(self.chanissues)
        except Exception as e:
            LOGGER.debug("Got EXCEPTION: %s", e)

