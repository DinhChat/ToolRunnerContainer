# README

This README would normally document whatever steps are necessary to get the
application up and running.

Things you may want to cover:

* Ruby version

* System dependencies

* Configuration

* Database creation

* Database initialization

* How to run the test suite

* Services (job queues, cache servers, search engines, etc.)

* Deployment instructions

* ...
docker build -t tool-sandbox-app:latest . 
docker run -d -p 3000:3000 -e RAILS_MASTER_KEY=5baaa1f270c4e9d07b0f4c1efea8f892 -v /var/run/docker.sock:/var/run/docker.sock --name tool_sandbox --group-add 988 tool-sandbox-app:latest
