---
layout: default
title: archive
author: inferigang
image: /assets/banners/default.png
description: "The map of all our papers"
---

# Archive

Browse all posts by month and year.

{% assign postsByYearMonth = site.posts | group_by_exp: "post", "post.date | date: '%B %Y'" %}
{% for yearMonth in postsByYearMonth %}
  <h2>{{ yearMonth.name }}</h2>
  <ul>
    {% for post in yearMonth.items %}
      <li><a href="{{ post.url }}">{{ post.title }}</a> by <a href="{{ post.author_url }}">@{{ post.author }}</a></li>
    {% endfor %}
  </ul>
{% endfor %}
