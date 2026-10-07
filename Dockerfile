FROM php:8.3-cli

# PATCH: base image no longer includes the SQLite headers pdo_sqlite needs to compile.
RUN apt-get update && apt-get install -y --no-install-recommends libsqlite3-dev \
    && rm -rf /var/lib/apt/lists/* \
    && docker-php-ext-install pdo_sqlite

WORKDIR /app
COPY . .
# PATCH: was chmod 777 (any user in the container could read/replace the database). Owner-only now.
RUN mkdir -p /app/data && chmod 700 /app/data

ENV PORT=3000
ENV DATABASE_PATH=/app/data/locker.db
EXPOSE 3000

CMD ["sh", "-c", "php -S 0.0.0.0:${PORT} -t public public/router.php"]
