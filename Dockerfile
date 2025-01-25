FROM node:18-alpine
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
EXPOSE 4000
CMD ["npm", "start"]
LABEL maintainer="chiemelaumeh1@gmail.com"
LABEL application="CICD server application"