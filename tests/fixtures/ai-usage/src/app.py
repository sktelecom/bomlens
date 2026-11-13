# Copyright 2026 SK Telecom Co., Ltd.
# SPDX-License-Identifier: Apache-2.0

"""Fixture: a service that calls a hosted model and loads a hub model locally."""
from openai import OpenAI
from transformers import AutoModel

SYSTEM_PROMPT = "You are a helpful assistant."


def answer(question):
    client = OpenAI()
    reply = client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "system", "content": SYSTEM_PROMPT}, {"role": "user", "content": question}],
    )
    return reply.choices[0].message.content


def local_model():
    return AutoModel.from_pretrained("meta-llama/Llama-3.1-8B-Instruct")
