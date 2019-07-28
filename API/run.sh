docker stop auth_website_1 auth_laptop-service_1 auth_mongodb_1
docker rm auth_website_1 auth_laptop-service_1 auth_mongodb_1
docker image rm auth_laptop-service demo flask-sample-on 8ba7cc1c8357
docker-compose up
