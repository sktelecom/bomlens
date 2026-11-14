// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0
// foo.ko.md beside foo.md becomes the Korean page ko/foo, as in the MkDocs site.
import { defineCollection } from 'astro:content';
import { docsLoader } from '@astrojs/starlight/loaders';
import { docsSchema } from '@astrojs/starlight/schema';

const generateId = ({ entry }: { entry: string }) => {
  const id = entry.replace(/\.md$/, '');
  return id.endsWith('.ko') ? `ko/${id.slice(0, -3)}` : id;
};

export const collections = {
  docs: defineCollection({ loader: docsLoader({ generateId }), schema: docsSchema() }),
};
