FROM    python:3
LABEL   maintainer = "Caleb Bradford <@calebkbradford>"

ENV WEBROOT="/var/www"

WORKDIR ${WEBROOT}
RUN     wget https://raw.githubusercontent.com/ibnesayeed/webserver-tester/master/sample/cs531-test-files.tar.gz \
        && tar xvzf cs531-test-files.tar.gz \
        && rm -rf cs531-test-files.tar.gz

WORKDIR /app

COPY    src/server.py /app
COPY    settings /app/settings
COPY    access.log /app

RUN     chmod a+x server.py
RUN     pip install pyyaml

ENTRYPOINT [ "./server.py" ]
