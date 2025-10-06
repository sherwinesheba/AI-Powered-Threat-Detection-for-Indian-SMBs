#!/bin/bash
docker build -t cybershield .
docker run -p 5000:5000 -e OPENAI_API_KEY=yourkey -e MAIL_USERNAME=yourmail cybershield
