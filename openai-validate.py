#!/bin/python3
# Adapted from https://stackoverflow.com/a/77814220
import openai
import os


def check_openai_api_key(api_key):
    client = openai.OpenAI(api_key=api_key)
    try:
        client.models.list()
    except openai.AuthenticationError:
        return False
    else:
        return True


if __name__ == "__main__":
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        print("Please specify OPENAI_API_KEY environment variable")
        exit()
    
    if check_openai_api_key(api_key):
        print("Valid OpenAI API key.")
    else:
        print("Invalid OpenAI API key.")
