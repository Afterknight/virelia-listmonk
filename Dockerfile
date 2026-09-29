FROM listmonk/listmonk:latest

ENV LISTMONK_app__address=0.0.0.0:3000

CMD ["sh", "-c", "./listmonk --install --idempotent --yes --config '' && ./listmonk --upgrade --yes --config '' && exec ./listmonk --config ''"]
