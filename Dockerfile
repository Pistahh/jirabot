FROM alpine
RUN adduser -D -H jirabot
RUN apk add --update python3
RUN python3 -m pip install rtmbot jira
RUN mkdir /jirabot /jirabot/etc /jirabot/log
RUN chown -R jirabot /jirabot/log
ADD plugins /jirabot/plugins
ADD runbot.sh /jirabot/runbot.sh
USER jirabot
ENTRYPOINT /jirabot/runbot.sh
