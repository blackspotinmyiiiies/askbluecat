+++
title = "GitHub နဲ့ Cloudflare Pages သုံးပြီး Free Website ဘယ်လိုထောင်မလဲ"
date = 2026-01-15T00:00:00Z
draft = false
description = "Hugo Framework ကိုသုံးပြီး Blowfish theme နဲ့ အတူတူ Cloudflare ပေါ် မှာ pages ထောင်ပြီး GitHub ကနေ Static Websiteလုပ်နည်း"
tags = ["hugo", "cloudflare", "github", "blowfish", "static-site"]
+++
![My Hugo + Cloudflare setup](/img/Gemini_Generated_Image_g1aiiag1aiiag1ai.png)

Hugo + GitHub + Cloudflare Pages ပေါင်းပြီး Free static website ထောင်လို့ ရပါတယ်။ 
ဘာတွေလိုမလဲဆိုတော့ 
    Hugo installed locally (hugo ကို စက်ထဲမှာ install လုပ်ထားပါ) 

    GitHub account တစ်ခု ဖွင့်ထားပါ။ 

    Cloudflare account တစ်ခု ဖွင့်ထားပါ။ 

    Git သုံးနည်းလေးနည်းနည်းလောက် သိထားရပါမယ်။
 AI တွေကို မေးပြီးလိုက်လုပ်လည်းရတယ်။ နည်းနည်းလောက်သိထားရင်တော့ ပိုကောင်းတာပေါ့လေ။

Step 1: Create repo on GitHub and Build the site locally

ပထမဦးဆုံး  GitHub ပေါ်မှာ Repo တစ်ခု လုပ်လိုက်ပါမယ်။ ပြီးတော့ hugo နဲ့ site တစ်ခု လုပ်မယ်။ ဒါကတော့ locally ကိုယ်စက်ထဲမှာ လုပ်ရမှာဖြစ်တယ်။ GitHub ပေါ်မှာ လုပ်တာကတော့ သူပြထားတဲ့ အတိုင်း လုပ် click လိုက်ရင် ရပါပြီ။ 

```bash
hugo new site askbluecat
```
ပြီးရင် Blowfish ကို download ဆွဲပြီး သူ့ရဲ့ config ဖိုင်တွေကို ကော်ပိ ယူလိုက်မယ်။ 
မြန်မာ လို မြင်ရဖို့ ဒီ Config ဖိုင် လေးတွေထည့်လိုက်တယ်။ 
    
    languages.en.toml

    languages.mm.toml

    menus.en.toml

    menus.mm.toml

Step 2: Push to GitHub

``` bash
git init
git add .
git commit -m "First commit"
git branch -M main
git remote add origin https://github.com/yourusername/askbluecat.git
git push -u origin main
```

Step 3: Deploy with Cloudflare Pages
ဒီအဆင့်မှာတော့ Cloudflare ပေါ်မှာ page တစ်ခု လုပ်ပြီး GitHub နဲ့ ချိတ်ရမယ်။ လွယ်ပါတယ်။ သူပြထားတာတွေကို လိုက်နှိပ်ရုံပါပဲ။

    Connected my GitHub repo

    Build command: hugo --gc --minify

    Output directory: public

    Production branch: main

Step 4: နည်းနည်း ဟိုပြင် ဒီ ပြင်ရင်း ဝယ်ထားတဲ့ကိုယ့် Domain ကို ထည့်လိုက်မယ်။ 

    Replaced Blowfish’s default favicons with my own logo in static/

    Added my custom domain askbluecat.com in Cloudflare Pages

ဒါပါပဲ။ ဘယ်လို လုပ်ရမလဲ အသေးစိတ်သိချင်ရင် ဆက်သွယ်မေးမြန်းလို့ရပါတယ်။ 
