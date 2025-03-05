#!/bin/sh

set -e

npm i -c --silent

rm -rf ./dist

mkdir -p ./dist/templates_cms ./dist/static/external
cp -r ./src/templates/* ./dist/templates_cms
cp -r ./src/static/* ./dist/static/external
cp -r ./node_modules/@cmsgov/design-system/dist/fonts ./dist/static/external

npm run build:css