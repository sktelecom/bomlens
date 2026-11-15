// Copyright 2026 SK Telecom Co., Ltd.
// SPDX-License-Identifier: Apache-2.0
//
// Two per-page fixes Starlight's config cannot express:
//   - The edit link must point at the source under docs/ (or docs-site/home/ for the
//     home pages), not at the copy in src/content/docs.
//   - og:locale uses the full locale (ko_KR, en_US) that link previews expect.
import { defineRouteMiddleware } from '@astrojs/starlight/route-data';

const repo = 'https://github.com/sktelecom/bomlens/edit/main';

export const onRequest = defineRouteMiddleware((context) => {
  const route = context.locals.starlightRoute;
  const id = route.entry.id;
  const ko = id === 'ko' || id.startsWith('ko/');
  const page = id === 'ko' || id === '' ? 'index' : ko ? id.slice(3) : id;
  const isHome = page === 'index';
  const file = isHome
    ? `docs-site/home/index${ko ? '.ko' : ''}.mdx`
    : `docs/${page}${ko ? '.ko' : ''}.md`;
  if (route.editUrl) route.editUrl = new URL(`${repo}/${file}`);

  for (const item of route.head) {
    if (item.tag === 'meta' && item.attrs?.property === 'og:locale') {
      item.attrs.content = ko ? 'ko_KR' : 'en_US';
    }
  }
});
