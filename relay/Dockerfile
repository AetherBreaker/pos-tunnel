FROM alpine:3.22

RUN apk add --no-cache openssh-server iproute2 \
 && adduser -D -H -s /sbin/nologin tunnel \
 && adduser -D -H -s /sbin/nologin jump \
 && adduser -D -h /data/state -s /bin/sh ctl \
 && addgroup -S keyreader && adduser -S -D -H -G keyreader -s /sbin/nologin keyreader \
 && printf '%s\n' 'tunnel:*' 'jump:*' 'ctl:*' | chpasswd -e

COPY sshd_config /etc/ssh/sshd_config
COPY --chmod=755 tunnelctl reaper tunnel-keys /usr/local/bin/
COPY --chmod=755 entrypoint.sh /entrypoint.sh
RUN echo '* * * * * /usr/local/bin/reaper' > /etc/crontabs/root

EXPOSE 2222
VOLUME /data
ENTRYPOINT ["/entrypoint.sh"]
