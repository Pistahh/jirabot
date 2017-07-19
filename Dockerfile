FROM alpine
RUN apk add --update python3
RUN python3 -m pip install rtmbot jira
ADD plugins /jirabot/plugins
ADD runbot.sh /jirabot/bin/runbot.sh
RUN mkdir /jirabot/etc
RUN adduser -D -H bot
USER bot
ENTRYPOINT /jirabot/bin/runbot.sh
