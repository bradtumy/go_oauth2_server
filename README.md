# go_oauth2_server

based on @cyantarek https://hackernoon.com/build-your-own-oauth2-server-in-go-7d0f660732c3

## Register app to get client_id and client_secret
Run the code and go to http://localhost:9096/credentials route to register and get client_id and client_secret

## Get access token with the client credentials grant flow
http://localhost:9096/token?grant_type=client_credentials&client_id=YOUR_CLIENT_ID&client_secret=YOUR_CLIENT_SECRET&scope=all

## Use the token to get access to the protected endpoint
http://localhost:9096/protected?access_token=YOUR_ACCESS_TOKEN
