// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';
import { unified } from '@astrojs/markdown-remark';
import remarkMdLinks from './src/plugins/remark-md-links.mjs';

// The site is served under a sub-path. During the migration the new site is built
// next to the MkDocs site under /bomlens/next/; DOCS_BASE switches it to /bomlens/.
const base = process.env.DOCS_BASE || '/bomlens/next';
const slashBase = base.endsWith('/') ? base : `${base}/`;

export default defineConfig({
  site: 'https://sktelecom.github.io',
  base,
  trailingSlash: 'always',
  markdown: { processor: unified({ remarkPlugins: [[remarkMdLinks, { base: slashBase }]] }) },
  integrations: [
    starlight({
      title: 'BomLens',
      defaultLocale: 'root',
      locales: { root: { label: 'English', lang: 'en' }, ko: { label: '한국어', lang: 'ko' } },
      customCss: ['./src/styles/github-like.css'],
      tableOfContents: { minHeadingLevel: 2, maxHeadingLevel: 3 },
      sidebar: [
        { label: 'Get started', translations: { ko: '빠른 시작' }, items: ['concepts/what-is-sbom', 'start/first-scan', 'start/no-cli', 'reference/ui'] },
        { label: 'Guides', translations: { ko: '가이드' }, items: [{ autogenerate: { directory: 'guides' } }] },
        { label: 'Reference', translations: { ko: '레퍼런스' }, items: [{ autogenerate: { directory: 'reference' } }] },
        { label: 'Concepts', translations: { ko: '개념' }, items: [{ autogenerate: { directory: 'concepts' } }] },
      ],
    }),
  ],
});
