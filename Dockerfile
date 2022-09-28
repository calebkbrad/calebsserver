FROM    python:3
LABEL   maintainer = "Caleb Bradford <@calebkbradford>"

COPY    src/server.py /calebsserver
WORKDIR /calebsserver

RUN     chmod a+x server.py

ENTRYPOINT [ "./server.py" ]