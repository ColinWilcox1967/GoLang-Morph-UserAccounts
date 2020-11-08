@echo off 
curl --header "Content-Type: application/json" --data  "{\"username\":\"user1\",\"password\":\"\"}" http://localhost:8080/login
