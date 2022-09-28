FROM    python:3
LABEL   maintainer = "Caleb Bradford <@calebkbradford>"

COPY    src/server.py ./

RUN     chmod a+x server.py

ENTRYPOINT [ "./server.py" ]