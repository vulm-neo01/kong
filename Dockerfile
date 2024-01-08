FROM kong
USER root
RUN apt-get update && \
    apt-get install -y redis-server python3 python3-pip python3-dev musl-dev libffi-dev gcc g++ file make
RUN pip3 install kong-pdk
RUN pip3 install pyjwt redis
WORKDIR /opt/kong-python-pdk
COPY ./kong-py-plugins .
COPY ./kong-python-pdk .
#COPY ./jwt-auth .
# reset back the defaults
USER kong
ENTRYPOINT ["/docker-entrypoint.sh"]
EXPOSE 8000 8443 8001 8444
STOPSIGNAL SIGQUIT
HEALTHCHECK --interval=10s --timeout=10s --retries=10 CMD kong health
CMD ["kong", "docker-start"]