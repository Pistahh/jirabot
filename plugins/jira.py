
from __future__ import print_function
from __future__ import unicode_literals

from rtmbot.core import Plugin
import re
import jira
import logging
from collections import defaultdict
import os
import sys

DESC_LEN = 160

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
                "name": chan["name"],
                "hushed": False,
                "verbose": True
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
        self.chanissues = defaultdict(int)
        self.chanmsgs = defaultdict(int)

    def get_issue(self, issue):
        LOGGER.debug("Trying to get issue %s", issue)
        i = self.jira.issue(issue)
        data = {
            'url': None,
            'issue': issue,
            'description': None,
            'status': None,
            'summary': None,
            'priority': None,
            'priority_iconurl': None,
            'issuetype': None,
            'issuetype_iconurl': None,
            'creator': None,
            'assignee': None
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
            data['creator'] = i.fields.creator.name
        except:
            pass

        try:
            data['assignee'] = i.fields.assignee.name
        except:
            pass


        return data
        #except jira.exceptions.JIRAERROR:
        #    pass

    def send_issue_verbose(self, channel_id, idata):
        att = [
                {
                    "text": idata["description"],
                    "fields": [
                        {
                            "title": "Status",
                            "value": idata["status"] or "N/A",
                            "short": True
                        },
                        {
                            "title": "Priority",
                            "value": idata["priority"] or "N/A",
                            "short": True
                        },
                        {
                            "title": "Created by",
                            "value": idata["creator"] or "N/A",
                            "short": True
                        },
                        {
                            "title": "Assigned to",
                            "value": idata["assignee"] or "N/A",
                            "short": True
                        }
                    ],
                }
            ]
        LOGGER.debug("Sending message with issue data")
        self.slack_client.api_call("chat.postMessage",
                                    channel=channel_id,
                                    as_user=True,
                                    text="<{}|{}> {}".format(idata['url'], idata["issue"], idata["summary"] or ""),
                                    attachments=att)

    def send_issue_simple(self, channel_id, idata):

        msg = "<{}|{}>".format(idata['url'], idata["issue"])

        l = []
        if idata["status"]: l.append(idata["status"])
        if idata["priority"] and idata["priority"] != "Unset": l.append(idata["priority"])
        if idata["issuetype"]: l.append(idata["issuetype"])

        cre = idata["creator"]
        ass = idata["assignee"]

        if cre: cre = "@{}".format(cre)
        if ass: ass = "@{}".format(ass)
        if cre == ass:
            ctoa = cre
        else:
            ctoa = "{} -> {}".format(cre or "", ass or "")


        desc = idata["description"] or ""

        desc = re.sub( '\s+', ' ', desc).strip()

        if len(desc) > DESC_LEN:
            desc = desc[:DESC_LEN].rsplit(' ', 1)[0]+"..."

        msg += " *{}* [{} | {}]\n{}".format(idata["summary"], " ".join(l), ctoa, desc)
        LOGGER.debug("Sending message with issue data")
        LOGGER.debug("MSG=%s", msg)
        self.slack_client.api_call("chat.postMessage",
                                    channel=channel_id,
                                    as_user=True,
                                    link_names=1,
                                    text=msg)

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
                                           text="For help please see https://info.citrite.net/display/JIRA/Jirabot")
                return

            if not channel_id in self.chans:
                self.chans[channel_id] = {
                    "name": "somethingnew, need to fetch :-)",
                    "hushed": False,
                    "verbose": True,
                    "latest_ts": '0'
                }

            channel = self.chans[channel_id]
            channel_name = channel["name"]
            LOGGER.debug("Channel: %s", channel_name)
            if data['ts'] <= channel["latest_ts"]:
                LOGGER.debug("Ignoring old message")
                return

            self.chanmsgs[channel_name] += 1

            text = data['text']
            if channel['hushed']:
                m = []
            else:
                LOGGER.debug("Searching for issue patterns")
                m = ISSUE_RE.findall(text)

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
                    if channel.get('verbose', True):
                        self.send_issue_verbose(channel_id, idata)
                    else:
                        self.send_issue_simple(channel_id, idata)

            if "jirabot" in text and "evanesco" in text:
                LOGGER.debug("leaving channel %s", channel_id)
                res = self.slack_client.api_call("channels.leave",
                                           channel=channel_id)
                LOGGER.debug("RES=%s", res)
                return
            if "jirabot" in text and "hush" in text:
                LOGGER.debug("Keeping channel %s quiet", channel_id)
                channel['hushed'] = True
                return

            if "jirabot" in text and "talk" in text:
                LOGGER.debug("Talking again in channel %s", channel_id)
                channel['hushed'] = False
                return

            if "jirabot" in text and "verbose on" in text:
                LOGGER.debug("Setting verbose on in channel %s", channel_id)
                channel['verbose'] = True
                return

            if "jirabot" in text and "verbose off" in text:
                LOGGER.debug("Setting verbose off in channel %s", channel_id)
                channel['verbose'] = False
                return

            if "jirabot" in text and "help" in text:
                self.slack_client.api_call("chat.postMessage",
                                           channel=channel_id,
                                           as_user=True,
                                           text="You may find help at https://info.citrite.net/display/JIRA/Jirabot")
                return
            if "jirabot" in text and "ping" in text:
                self.slack_client.api_call("chat.postMessage",
                                           channel=channel_id,
                                           as_user=True,
                                           text="Pong :)")
                return



        except Exception as e:
            LOGGER.debug("Got EXCEPTION: %s", e)

