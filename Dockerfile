FROM ruby:3.2-slim

RUN apt-get update && apt-get install -y \
    ffmpeg \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY Gemfile ./

RUN bundle install

COPY . .

RUN chmod +x bin/*

RUN mkdir -p logs/streams

EXPOSE 8080

CMD ["./bin/streamripper", "web", "--port", "8080", "--host", "0.0.0.0"]
