+++
title = "GitHub နဲ့ Cloudflare Pages သုံးပြီး Free Website ဘယ်လိုထောင်မလဲ"
date = 2026-01-15T00:00:00Z
draft = false
description = "A quick guide to hosting a Hugo + Blowfish site with GitHub and Cloudflare."
tags = ["hugo", "cloudflare", "github", "blowfish", "static-site"]
featuredImage = "/img/Gemini_Generated_Image_g1aiiag1aiiag1ai.png"
+++

Hugo + GitHub + Cloudflare Pages is a solid combo for a fast, free, and secure static website. I use it for my blog, but it works great for portfolios or docs too.
What you’ll need

    Hugo installed locally

    GitHub account

    Cloudflare account

    A little Git experience

Step 1: Build the site locally

I started with the Blowfish theme on Parrot OS:
bash

hugo new site askbluecat

Then I added Blowfish as a submodule and set up config files in config/_default.
To support English and Myanmar languages, I added:

    languages.en.toml

    languages.mm.toml

    menus.en.toml

    menus.mm.toml

Then I updated hugo.toml to let visitors switch between languages.
Step 2: Push to GitHub
bash

git init
git add .
git commit -m "First commit"
git branch -M main
git remote add origin https://github.com/blackspotinmyiiiies/askbluecat.git
git push -u origin main

Step 3: Deploy with Cloudflare Pages

On Cloudflare Pages:

    Connected my GitHub repo

    Build command: hugo --gc --minify

    Output directory: public

    Production branch: main

Now every push to main triggers an automatic build and deploy.
Step 4: Personal touches

    Replaced Blowfish’s default favicons with my own logo in static/

    Added my custom domain askbluecat.com in Cloudflare Pages

That’s it — my site is live.
