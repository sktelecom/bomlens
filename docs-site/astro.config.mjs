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

// Pages that moved before this site existed. The root-level names are the old
// Korean-only pages, the /en/ names are the old English copies.
const moved = {
  'getting-started': 'ko/start/first-scan',
  'quickstart-no-cli': 'ko/start/no-cli',
  'scenarios-guide': 'ko/guides/by-input',
  'usage-guide': 'ko/reference/cli',
  'notice-and-security': 'ko/guides/reports',
  'examples-guide': 'ko/reference/ecosystems',
  'docker-image': 'ko/reference/docker-image',
  'architecture': 'ko/concepts/architecture',
  'firmware-analysis-guide': 'ko/guides/firmware',
  'supplier-sbom-validation': 'ko/guides/supplier-sbom',
  'contributing/package-manager-guide': 'ko/contribute/package-managers',
  'contributing/testing-guide': 'ko/contribute/testing',
  'en': '',
  'en/getting-started': 'start/first-scan',
  'en/quickstart-no-cli': 'start/no-cli',
  'en/scenarios-guide': 'guides/by-input',
  'en/usage-guide': 'reference/cli',
  'en/notice-and-security': 'guides/reports',
  'en/examples-guide': 'reference/ecosystems',
  'en/docker-image': 'reference/docker-image',
  'en/architecture': 'concepts/architecture',
  'en/firmware-analysis-guide': 'guides/firmware',
  'en/supplier-sbom-validation': 'guides/supplier-sbom',
  'en/contributing/package-manager-guide': 'contribute/package-managers',
  'en/contributing/testing-guide': 'contribute/testing',
};
const redirects = Object.fromEntries(
  Object.entries(moved).map(([from, to]) => [`/${from}/`, `${slashBase}${to ? `${to}/` : ''}`]),
);

// Visit analytics (GoatCounter, no cookies, no personal data). Set the site code to
// turn it on; empty means no script is emitted.
const goatcounter = '';

export default defineConfig({
  site: 'https://sktelecom.github.io',
  base,
  trailingSlash: 'always',
  redirects,
  markdown: { processor: unified({ remarkPlugins: [[remarkMdLinks, { base: slashBase }]] }) },
  integrations: [
    starlight({
      title: 'BomLens',
      defaultLocale: 'root',
      locales: { root: { label: 'English', lang: 'en' }, ko: { label: '한국어', lang: 'ko' } },
      favicon: '/favicon.svg',
      customCss: ['./src/styles/bomlens-tokens.css', './src/styles/github-like.css'],
      social: [{ icon: 'github', label: 'GitHub', href: 'https://github.com/sktelecom/bomlens' }],
      // The edit link target is set per page in src/routeData.ts. The base URL here only
      // switches the link on.
      editLink: { baseUrl: 'https://github.com/sktelecom/bomlens/edit/main/' },
      routeMiddleware: './src/routeData.ts',
      head: goatcounter
        ? [{ tag: 'script', attrs: { async: true, src: '//gc.zgo.at/count.js', 'data-goatcounter': `https://${goatcounter}.goatcounter.com/count` } }]
        : [],
      components: {
        PageTitle: './src/components/PageTitle.astro',
        Footer: './src/components/Footer.astro',
        Head: './src/components/Head.astro',
      },
      expressiveCode: {
        themes: ['github-light', 'github-dark'],
        // No grammar exists for Modelica; show it as plain text without a warning.
        shiki: { langAlias: { modelica: 'text' } },
        // Shell blocks get no window bar; the copy button stays.
        defaultProps: { frame: 'code' },
        styleOverrides: {
          borderRadius: '0.5rem',
          frames: { terminalTitlebarDotsForeground: 'transparent', terminalTitlebarDotsOpacity: '0' },
        },
      },
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
