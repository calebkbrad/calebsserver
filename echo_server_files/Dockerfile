FROM    python:3
LABEL   maintainer = "Caleb Bradford <@calebkbradford>"

COPY    echo_server.py /app/
WORKDIR /app

RUN     chmod a+x echo_server.py

ENTRYPOINT [ "./echo_server.py" ]