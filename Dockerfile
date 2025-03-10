FROM ruby:latest

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    git \
    && rm -rf /var/lib/apt/lists/*

COPY . /site

WORKDIR /site

RUN bundle install

EXPOSE 3000
CMD [ "bundle", "exec", "jekyll", "serve", "-H" ,"0.0.0.0"]
