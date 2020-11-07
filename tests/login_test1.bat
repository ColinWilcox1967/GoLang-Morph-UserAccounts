@echo off 
curl --header "Content-Type: application/json" --data  "{\"username\":\"user1\",\"password\":\"pass1\"}" http://localhost:8080/login
