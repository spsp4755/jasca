# 공식 이미지에서 쓰지 않는 파일만 뺍니다. postgres.yaml은 UID 999로 실행하므로 root 전환용 gosu가 필요 없습니다.
# 이 이미지는 root로 실행하지 마세요. 자체서명 snakeoil 키는 모든 복사본이 같은 키라 쓰지 않습니다.
FROM postgres:17.11-bookworm@sha256:665dc7b37ac52a17e298511414c21d23ffa4e6a6ef6225b3e5d59c7afb35e994
RUN rm -f /usr/local/bin/gosu /etc/ssl/private/ssl-cert-snakeoil.key /etc/ssl/certs/ssl-cert-snakeoil.pem
USER 999:999
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s CMD ["pg_isready", "-h", "127.0.0.1"]
