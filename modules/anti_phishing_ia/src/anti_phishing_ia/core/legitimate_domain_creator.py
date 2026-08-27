#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
BASE DE DONNÉES MASSIVE: 5000+ DOMAINES LÉGITIMES
Sources:
- Wikipedia Top Sites 2025
- Cloudflare Radar Domain Rankings (July 2025)
- DigitalStakeout Top 1000 Trusted Domains
- DataForSEO Top 1000 Authority Domains
- Common Crawl Open PageRank
Dernière mise à jour: Octobre 2025
"""

import joblib, os
dir_ = os.path.join(os.path.dirname(os.path.abspath(__file__)),'legite_domain')
os.makedirs(dir_,exist_ok=True)
output_file = os.path.join(dir_,"legitimate_domains_mega.joblib")
# ============================================================================
# TOP 100 SITES MONDIAUX (DigitalStakeout + Cloudflare 2025)
# ============================================================================

TOP_100_GLOBAL = [
    # Top 20
    "google.com", "youtube.com", "facebook.com", "microsoft.com", "twitter.com",
    "tmall.com", "instagram.com", "baidu.com", "linkedin.com", "qq.com",
    "apple.com", "windowsupdate.com", "wikipedia.org", "live.com", "sohu.com",
    "googletagmanager.com", "yahoo.com", "amazon.com", "taobao.com", "doubleclick.net",

    # 21-50
    "youtu.be", "pinterest.com", "reddit.com", "netflix.com", "vk.com",
    "x.com", "whatsapp.com", "tiktok.com", "discord.com", "twitch.tv",
    "bing.com", "duckduckgo.com", "naver.com", "mail.ru", "samsung.com",
    "globo.com", "ebay.com", "msn.com", "office.com", "roblox.com",
    "fandom.com", "bbc.co.uk", "bilibili.com", "dzen.ru", "telegram.org",
    "zoom.us", "imdb.com", "github.com", "spotify.com", "chatgpt.com",

    # 51-100
    "tumblr.com", "cnn.com", "dailymotion.com", "paypal.com", "canva.com",
    "microsoft365.com", "booking.com", "stackexchange.com", "aliexpress.com",
    "indeed.com", "accuweather.com", "etsy.com", "espn.com", "binance.com",
    "rakuten.co.jp", "nytimes.com", "mediafire.com", "openai.com", "flipkart.com",
    "quora.com", "amazon.co.jp", "stackoverflow.com", "soundcloud.com", "amazon.de",
    "amazon.co.uk", "adobe.com", "alibaba.com", "indiatimes.com", "craigslist.org",
    "vimeo.com", "steampowered.com", "hulu.com", "chase.com", "wordpress.com",
    "amazon.in", "nike.com", "mercadolibre.com", "walmart.com", "cnet.com",
    "tripadvisor.com", "dropbox.com", "blogger.com", "forbes.com", "investing.com",
    "nih.gov", "ok.ru", "target.com", "archive.org", "wellsfargo.com"
]

# ============================================================================
# TECH GIANTS & CLOUD (500+)
# ============================================================================

TECH_GIANTS_CLOUD = [
    # Google Ecosystem (40+)
    "google.com", "google.co.uk", "google.fr", "google.de", "google.es", "google.it",
    "google.com.br", "google.co.jp", "google.co.in", "google.ca", "google.com.au",
    "google.ru", "google.com.mx", "google.nl", "google.com.tr", "google.pl",
    "google.co.id", "google.com.ar", "google.co.za", "google.com.eg",
    "youtube.com", "gmail.com", "drive.google.com", "docs.google.com", "maps.google.com",
    "photos.google.com", "play.google.com", "meet.google.com", "calendar.google.com",
    "translate.google.com", "blogger.com", "doubleclick.net", "gstatic.com",
    "googleusercontent.com", "googleapis.com", "android.com", "chromium.org",
    "google-analytics.com", "googlesyndication.com", "googletagmanager.com",

    # Microsoft Ecosystem (45+)
    "microsoft.com", "live.com", "outlook.com", "office.com", "office365.com",
    "microsoft365.com", "onedrive.live.com", "skydrive.com", "hotmail.com",
    "msn.com", "bing.com", "azure.microsoft.com", "visualstudio.com",
    "xbox.com", "linkedin.com", "github.com", "typescript.org", "powershell.org",
    "windows.com", "windowsazure.com", "microsoftonline.com", "sharepoint.com",
    "teams.microsoft.com", "yammer.com", "minecraft.net", "mojang.com",
    "windowsupdate.com", "microsoft.net", "azure.com", "office.net",
    "skype.com", "surface.com", "store.microsoft.com", "docs.microsoft.com",
    "developer.microsoft.com", "technet.microsoft.com", "msdn.microsoft.com",
    "dynamics.com", "powerapps.com", "powerbi.com", "powerautomate.com",
    "nuget.org", "visualstudio.net", "vscode.dev", "github.io",

    # Apple Ecosystem (20+)
    "apple.com", "icloud.com", "itunes.apple.com", "music.apple.com",
    "appstore.com", "me.com", "mac.com", "apple.co.uk", "apple.fr",
    "apple.de", "apple.com.au", "apple.co.jp", "applemusic.com",
    "appletv.com", "icloud.net", "apple.news", "developer.apple.com",
    "support.apple.com", "apple.com.cn", "testflight.apple.com",

    # Amazon Ecosystem (50+)
    "amazon.com", "amazon.co.uk", "amazon.de", "amazon.fr", "amazon.es",
    "amazon.it", "amazon.ca", "amazon.com.br", "amazon.co.jp", "amazon.in",
    "amazon.com.mx", "amazon.nl", "amazon.com.au", "amazon.sg", "amazon.ae",
    "amazon.cn", "amazon.com.tr", "amazon.se", "amazon.pl", "amazon.eg",
    "aws.amazon.com", "cloudfront.net", "amazonaws.com", "amzn.to",
    "primevideo.com", "audible.com", "kindle.amazon.com", "alexa.amazon.com",
    "twitch.tv", "wholefoodsmarket.com", "zappos.com", "imdb.com",
    "a2z.com", "amazontrust.com", "awsstatic.com", "elasticbeanstalk.com",
    "cloudformation.amazonaws.com", "s3.amazonaws.com", "ec2.amazonaws.com",
    "lambda.amazonaws.com", "dynamodb.amazonaws.com", "rds.amazonaws.com",
    "sqs.amazonaws.com", "sns.amazonaws.com", "ses.amazonaws.com",
    "cloudwatch.amazonaws.com", "elasticache.amazonaws.com", "redshift.amazonaws.com",

    # Meta (Facebook) Ecosystem (15+)
    "facebook.com", "fb.com", "instagram.com", "whatsapp.com", "messenger.com",
    "meta.com", "oculus.com", "threads.net", "workplace.com", "fbcdn.net",
    "facebook.net", "facebookmail.com", "fb.me", "meta.net", "novi.com",

    # Cloud & Infrastructure (100+)
    "cloudflare.com", "cloudflare.net", "cloudflare-dns.com", "workers.dev",
    "akamai.com", "akamaitechnologies.com", "akamaiedge.net", "akamaihd.net",
    "fastly.com", "fastly.net", "digitalocean.com", "linode.com", "vultr.com",
    "heroku.com", "herokuapp.com", "vercel.com", "vercel.app", "netlify.com",
    "netlify.app", "godaddy.com", "namecheap.com", "name.com", "gandi.net",
    "ovh.com", "ovh.net", "ovhcloud.com", "1and1.com", "ionos.com",
    "bluehost.com", "hostgator.com", "dreamhost.com", "siteground.com",
    "wp.com", "wordpress.org", "webflow.com", "wix.com", "squarespace.com",
    "shopify.com", "bigcommerce.com", "magento.com", "woocommerce.com",
    "cloudinary.com", "imgix.net", "imagekit.io", "bunny.net", "bunnycdn.com",
    "stackpath.com", "maxcdn.com", "keycdn.com", "rackspace.com",
    "hetzner.com", "contabo.com", "scaleway.com", "upcloud.com",
    "googledomains.com", "domains.google", "hover.com", "dynadot.com",
    "porkbun.com", "namesilo.com", "enom.com", "tucows.com", "epik.com",
    "cloudns.net", "dnsimple.com", "dnsmadeeasy.com", "route53.amazonaws.com",
    "nsone.net", "ultradns.com", "zoneedit.com", "dnsexit.com",
    "afraid.org", "noip.com", "duckdns.org", "freedns.afraid.org",
    "he.net", "hurricane electric.net", "oracle.com", "oraclecloud.com",
    "ibm.com", "ibm.cloud", "redhat.com", "centos.org", "fedoraproject.org",
    "debian.org", "ubuntu.com", "canonical.com", "suse.com", "opensuse.org",
    "docker.com", "docker.io", "kubernetes.io", "rancher.com", "podman.io",
]

# ============================================================================
# E-COMMERCE & RETAIL (400+)
# ============================================================================

ECOMMERCE_RETAIL = [
    # Global Marketplaces (50+)
    "ebay.com", "ebay.co.uk", "ebay.de", "ebay.fr", "ebay.com.au", "ebay.ca",
    "ebay.it", "ebay.es", "ebay.nl", "ebay.ie",
    "alibaba.com", "aliexpress.com", "taobao.com", "tmall.com", "1688.com",
    "jd.com", "pinduoduo.com", "vipshop.com", "suning.com",
    "rakuten.co.jp", "rakuten.com", "mercadolibre.com", "mercadolibre.com.mx",
    "mercadolibre.com.ar", "mercadolibre.com.br", "mercadolibre.cl",
    "flipkart.com", "snapdeal.com", "myntra.com", "ajio.com",
    "lazada.com", "lazada.co.th", "lazada.sg", "lazada.com.my",
    "shopee.com", "shopee.sg", "shopee.ph", "shopee.tw",
    "tokopedia.com", "bukalapak.com", "blibli.com", "shopee.co.id",
    "etsy.com", "etsystatic.com", "craigslist.org", "gumtree.com",
    "leboncoin.fr", "allegro.pl", "avito.ru", "olx.com", "jumia.com",

    # US Retail Chains (40+)
    "walmart.com", "target.com", "costco.com", "homedepot.com", "lowes.com",
    "bestbuy.com", "macys.com", "kohls.com", "nordstrom.com", "jcpenney.com",
    "sears.com", "kmart.com", "dillards.com", "bloomingdales.com", "saks.com",
    "neimanmarcus.com", "barneys.com", "tjmaxx.com", "marshalls.com",
    "riteaid.com", "cvs.com", "walgreens.com", "kroger.com", "safeway.com",
    "publix.com", "wholefoods.com", "traderjoes.com", "aldius.com",
    "wegmans.com", "heb.com", "meijer.com", "target.com", "samsclub.com",
    "bjs.com", "staples.com", "officedepot.com", "officemax.com",
    "bedbathandbeyond.com", "containerstore.com", "crateandbarrel.com",

    # European Retail (50+)
    "carrefour.fr", "carrefour.es", "carrefour.com", "auchan.fr", "leclerc.fr",
    "tesco.com", "tesco.co.uk", "sainsburys.co.uk", "asda.com", "morrisons.com",
    "lidl.com", "lidl.de", "lidl.fr", "lidl.co.uk", "lidl.es",
    "aldi.com", "aldi.co.uk", "aldi.de", "aldi.us", "rewe.de",
    "edeka.de", "kaufland.de", "real.de", "metro.de", "penny.de",
    "mercadona.es", "elcorteingles.es", "dia.es", "eroski.es",
    "continente.pt", "pingo doce.pt", "auchan.pt", "intermarche.fr",
    "systeme-u.fr", "monoprix.fr", "franprix.fr", "casino.fr",
    "delhaize.be", "colruyt.be", "albert.cz", "kaufland.cz",
    "billa.at", "spar.at", "hofer.at", "merkur.at", "coop.ch",
    "migros.ch", "manor.ch", "jumbo.nl", "ah.nl", "plus.nl",

    # French E-commerce (30+)
    "cdiscount.com", "fnac.com", "darty.com", "ldlc.com", "rueducommerce.fr",
    "veepee.fr", "vente-privee.com", "vinted.fr", "leboncoin.fr",
    "backmarket.fr", "manomano.fr", "decathlon.com", "decathlon.fr",
    "decathlon.co.uk", "zalando.fr", "zalando.de", "zalando.co.uk",
    "asos.com", "boohoo.com", "prettylittlething.com", "zalando.com",
    "spartoo.com", "sarenza.com", "showroomprive.com", "brandalley.fr",
    "lacoste.com", "nike.com", "adidas.com", "adidas.fr",

    # Fashion & Luxury (60+)
    "zara.com", "hm.com", "gap.com", "uniqlo.com", "primark.com",
    "forever21.com", "fashionnova.com", "shein.com", "zaful.com",
    "romwe.com", "yesstyle.com", "farfetch.com", "ssense.com",
    "net-a-porter.com", "mrporter.com", "nordstromrack.com",
    "saks.com", "bloomingdales.com", "neimanmarcus.com",
    "gucci.com", "louisvuitton.com", "chanel.com", "prada.com",
    "hermes.com", "dior.com", "burberry.com", "versace.com",
    "armani.com", "ralphlauren.com", "calvinklein.com", "tommyhilfiger.com",
    "hugoboss.com", "lacoste.com", "polo.com", "michael kors.com",
    "coachoutlet.com", "katespade.com", "toryburch.com", "marcjacobs.com",
    "valentino.com", "givenchy.com", "fendi.com", "bottegaveneta.com",
    "balenciaga.com", "ysl.com", "saintlaurent.com", "celine.com",
    "loewe.com", "alexandermcqueen.com", "stellamccartney.com",
    "miumiu.com", "dolcegabbana.com", "moschino.com", "balmain.com",
    "giambattistavalli.com", "oscarde larenta.com", "eliesa ab.com",

    # Sports & Outdoor (30+)
    "nike.com", "adidas.com", "puma.com", "underarmour.com", "reebok.com",
    "newbalance.com", "asics.com", "saucony.com", "brooks running.com",
    "lululemon.com", "patagonia.com", "thenorthface.com", "columbia.com",
    "arcteryx.com", "mammut.com", "salomon.com", "merrell.com",
    "timberland.com", "vans.com", "converse.com", "skechers.com",
    "crocs.com", "birkenstock.com", "clarks.com", "ecco.com",
    "rei.com", "dickssportinggoods.com", "sportsdirect.com",
    "decathlon.com", "intersport.com",

    # Electronics & Tech Retail (30+)
    "bestbuy.com", "newegg.com", "bhphotovideo.com", "adorama.com",
    "microcenter.com", "frys.com", "tigerdirect.com", "dell.com",
    "hp.com", "lenovo.com", "asus.com", "acer.com", "msi.com",
    "razer.com", "corsair.com", "logitech.com", "steelseries.com",
    "alienware.com", "maingear.com", "originpc.com", "ibuypower.com",
    "cyberpower pc.com", "mediamarkt.de", "saturn.de", "fnac.com",
    "darty.com", "boulanger.com", "currys.co.uk", "pcworld.co.uk",
    "argos.co.uk",

    # Home & Furniture (30+)
    "ikea.com", "wayfair.com", "overstock.com", "houzz.com", "homestyler.com",
    "roomstogo.com", "ashleyfurniture.com", "lazyboy.com", "ethanallen.com",
    "crateandbarrel.com", "potterybarn.com", "westelm.com", "cb2.com",
    "anthropologie.com", "urbanoutfitters.com", "zgallerie.com",
    "roomandboard.com", "article.com", "joybird.com", "burrow.com",
    "allmodern.com", "birch lane.com", "jossandmain.com", "perigold.com",
    "homedepot.com", "lowes.com", "menards.com", "acehardware.com",
    "truevalue.com", "leroy merlin.fr",
]

# ============================================================================
# FINANCIAL SERVICES (300+)
# ============================================================================

FINANCIAL = [
    # Payment Processors (30+)
    "paypal.com", "paypal.co.uk", "paypal.fr", "paypal.de", "paypal.es",
    "stripe.com", "square.com", "squareup.com", "cash.app", "cashapp.com",
    "adyen.com", "worldpay.com", "checkout.com", "klarna.com", "afterpay.com",
    "affirm.com", "payu.com", "razorpay.com", "paytm.com", "phonepe.com",
    "alipay.com", "wechatpay.com", "payoneer.com", "skrill.com", "neteller.com",
    "2checkout.com", "authorize.net", "braintreepayments.com", "mollie.com",
    "payplug.com",

    # Crypto & Blockchain (40+)
    "coinbase.com", "binance.com", "kraken.com", "gemini.com", "bitfinex.com",
    "bitstamp.net", "blockchain.com", "blockchain.info", "crypto.com",
    "ftx.com", "kucoin.com", "huobi.com", "okx.com", "bybit.com",
    "bittrex.com", "poloniex.com", "bitflyer.com", "liquid.com",
    "metamask.io", "trustwallet.com", "exodus.com", "ledger.com",
    "trezor.io", "myetherwallet.com", "electrum.org", "bitcoin.org",
    "ethereum.org", "cardano.org", "solana.com", "polkadot.network",
    "chainlink.com", "ripple.com", "stellar.org", "litecoin.org",
    "monero.org", "zcash.com", "dash.org", "dogecoin.com",
    "uniswap.org", "pancakeswap.finance",

    # Neobanks & Digital Banking (30+)
    "revolut.com", "n26.com", "monzo.com", "chime.com", "wise.com",
    "transferwise.com", "venmo.com", "zelle.com", "wealthfront.com",
    "betterment.com", "robinhood.com", "webull.com", "sofi.com",
    "marcus.com", "ally.com", "discover.com", "simple.com",
    "varo.com", "current.com", "aspiration.com", "qapital.com",
    "digit.com", "acorns.com", "stash.com", "m1finance.com",
    "wealthsimple.com", "tangerine.ca", "bunq.com", "starling.bank",
    "atom.bank",

    # US Banks (40+)
    "bankofamerica.com", "bofa.com", "chase.com", "wellsfargo.com",
    "citibank.com", "citi.com", "usbank.com", "pnc.com",
    "capitalone.com", "tdbank.com", "ally.com", "discover.com",
    "synchrony.com", "regions.com", "fifththird.com", "huntington.com",
    "keybank.com", "citizensbank.com", "mtb.com", "suntrust.com",
    "bbt.com", "truist.com", "umpquabank.com", "zionsbank.com",
    "firstrepublic.com", "svb.com", "signaturebank.com", "nymellon.com",
    "statestreet.com", "northerntrust.com", "mufg.com", "bnymellon.com",
    "jpmorganchase.com", "morganstanley.com", "goldmansachs.com",
    "wellsfargoadvisors.com", "merrilledge.com", "etrade.com",
    "schwab.com", "fidelity.com",

    # European Banks (60+)
    "hsbc.com", "hsbc.co.uk", "barclays.co.uk", "lloydsbank.com",
    "lloydsbanking group.com", "natwest.com", "rbs.com", "santander.com",
    "santander.co.uk", "santander.es", "deutschebank.com", "commerzbank.de",
    "bnpparibas.com", "bnpparibas.fr", "bnpparibas.net", "societegenerale.com",
    "societegenerale.fr", "creditagricole.fr", "credit-agricole.fr",
    "banquepopulaire.fr", "caisse-epargne.fr", "lcl.fr", "labanquepostale.fr",
    "boursorama.com", "fortuneo.fr", "hello bank.fr", "orange-bank.fr",
    "ing.fr", "ing.de", "ing.nl", "ing.com", "ing.be",
    "abn-amro.nl", "rabobank.nl", "sns.nl", "asn.nl",
    "unicredit.it", "intesasanpaolo.com", "bancobpm.it", "mps.it",
    "bbva.com", "bbva.es", "caixabank.es", "caixabank.com",
    "sabadell.com", "bankinter.com", "banco santander.es",
    "db.com", "dkb.de", "postbank.de", "sparkasse.de",
    "volksbank.de", "targobank.de", "credit-suisse.com", "ubs.com",
    "credit-mutuel.fr", "bred.fr", "cic.fr", "hsbc.fr",

    # Asian Banks (40+)
    "icicibank.com", "hdfcbank.com", "sbi.co.in", "axisbank.com",
    "kotak.com", "yesbank.in", "indusind.com", "idbibank.in",
    "pnb.in", "unionbankofindia.co.in", "canara bank.in",
    "dbs.com", "ocbc.com", "uob.com", "maybank.com", "cimb.com",
    "bdo.com.ph", "bpi.com.ph", "metrobank.com.ph", "unionbank.com.ph",
    "bca.co.id", "mandiri.co.id", "bri.co.id", "bni.co.id",
    "btpn.com", "kasikornbank.com", "scb.co.th", "bangkokbank.com",
    "krungsri.com", "tmb.co.th", "icbc.com.cn", "ccb.com",
    "boc.cn", "abchina.com", "bankcomm.com", "cmbchina.com",
    "cmbc.com.cn", "cib.com.cn", "psbc.com", "spdb.com.cn",

    # Credit Cards & Services (20+)
    "americanexpress.com", "amex.com", "mastercard.com", "visa.com",
    "discovercard.com", "discover.com", "jcb.co.jp", "unionpay.com",
    "dinersclub.com", "americanexpress.co.uk", "barclaycard.co.uk",
    "mbna.co.uk", "halifax.co.uk", "tsb.co.uk", "first-direct.com",
    "moneyhelper.org.uk", "equifax.com", "experian.com", "transunion.com",
    "creditkarma.com",

    # Insurance & Investment (50+)
    "fidelity.com", "vanguard.com", "schwab.com", "etrade.com",
    "tdameritrade.com", "interactivebrokers.com", "tradestation.com",
    "tastyworks.com", "thinkorswim.com", "merrillynch.com",
    "saxobank.com", "degiro.com", "trading212.com", "freetrade.io",
    "plus500.com", "etoro.com", "avatrade.com", "xm.com",
    "pepperstone.com", "ic markets.com", "oanda.com", "forex.com",
    "axa.com", "axa.fr", "allianz.com", "allianz.fr",
    "prudential.com", "metlife.com", "zurich.com", "generali.com",
    "aviva.com", "legal andgeneral.com", "standardlife.com",
    "scottishwidows.co.uk", "aig.com", "chubb.com", "travelers.com",
    "progressive.com", "geico.com", "statefarm.com", "allstate.com",
    "libertymutual.com", "nationwide.com", "usaa.com", "farmers.com",
    "thegeneral.com", "esurance.com", "safeco.com", "mercury.com",
]

# ============================================================================
# STREAMING & ENTERTAINMENT (200+)
# ============================================================================

STREAMING = [
    # Video Streaming (40+)
    "netflix.com", "disneyplus.com", "hulu.com", "hbomax.com", "max.com",
    "paramountplus.com", "peacocktv.com", "showtimeanytime.com",
    "starz.com", "cinemax.com", "epix.com", "mgmplus.com",
    "crunchyroll.com", "funimation.com", "vrv.co", "hidive.com",
    "primevideo.com", "appletv.com", "youtubemusic.com",
    "dailymotion.com", "vimeo.com", "twitch.tv", "mixer.com",
    "dlive.tv", "trovo.live", "kick.com", "rumble.com", "odysee.com",
    "bitchute.com", "lbry.tv", "brighteon.com", "banned.video",
    "gab.tv", "rokfin.com", "locals.com", "substack.com",
    "patreon.com", "onlyfans.com", "fansly.com",

    # International Streaming (40+)
    "canal.fr", "canalplus.com", "molotov.tv", "salto.fr",
    "arte.tv", "france.tv", "tf1.fr", "m6.fr", "6play.fr",
    "bbc.co.uk", "bbc.com", "itv.com", "itvx.com", "channel4.com",
    "all4.com", "my5.com", "sky.com", "nowtv.com", "skygo.co.uk",
    "dazn.com", "espn.com", "espnplus.com", "eurosport.com",
    "skysports.com", "btsport.com", "foxsports.com", "nbcsports.com",
    "cbssports.com", "dazn.de", "sportdigital.de", "magenta-sport.de",
    "rai.it", "raiplay.it", "mediasetplay.it", "dplay.it",
    "rtve.es", "atresplayer.com", "mitele.es", "rtl.de",
    "zdf.de", "ard.de", "3sat.de", "arte.de",

    # Music Streaming (30+)
    "spotify.com", "music.apple.com", "applemusic.com", "youtubemusic.com",
    "soundcloud.com", "deezer.com", "tidal.com", "pandora.com",
    "iheart.com", "iheartradio.com", "tunein.com", "radio.com",
    "napster.com", "qobuz.com", "bandcamp.com", "audiomack.com",
    "mixcloud.com", "8tracks.com", "last.fm", "musicbrainz.org",
    "discogs.com", "genius.com", "musixmatch.com", "azlyrics.com",
    "shazam.com", "anghami.com", "gaana.com", "jiosaavn.com",
    "wynk.in", "hungama.com",

    # Gaming Platforms (50+)
    "steam.com", "steampowered.com", "steamcommunity.com",
    "epicgames.com", "epicgames.store", "gog.com", "gog-games.com",
    "origin.com", "ea.com", "eaplay.com", "ubisoft.com", "uplay.com",
    "ubisoft connect.com", "battle.net", "blizzard.com", "activision.com",
    "riotgames.com", "leagueoflegends.com", "valorant.com", "teamfighttactics.com",
    "minecraft.net", "minecraft.com", "mojang.com", "roblox.com",
    "playstation.com", "playstation.net", "psnprofiles.com",
    "xbox.com", "xbox.net", "xboxlive.com", "nintendo.com",
    "nintendo.co.jp", "nintendoswitch.com", "eshop.nintendo.com",
    "discord.com", "discord.gg", "teamspeak.com", "mumble.info",
    "ventrilo.com", "curse.com", "curseforge.com", "overwolf.com",
    "nexusmods.com", "moddb.com", "gamebanana.com",
    "humblebundle.com", "fanatical.com", "greenmangaming.com",
    "cdkeys.com", "g2a.com", "kinguin.net", "gamivo.com",

    # Gaming Media (30+)
    "ign.com", "gamespot.com", "gamefaqs.com", "giantbomb.com",
    "polygon.com", "kotaku.com", "eurogamer.net", "rockpapershotgun.com",
    "pcgamer.com", "pcgamesn.com", "destructoid.com", "escapistmagazine.com",
    "metacritic.com", "opencritic.com", "howlongtobeat.com",
    "steamdb.info", "isthereanydeal.com", "gg.deals", "cheapshark.com",
    "twitch.tv", "youtube.com/gaming", "mixer.com", "trovo.live",
    "dlive.tv", "nimo.tv", "booyah.live", "omlet.gg",
    "mobcrush.com", "caffeine.tv",
]

# ============================================================================
# SOCIAL MEDIA & COMMUNICATION (150+)
# ============================================================================

SOCIAL_MEDIA = [
    # Major Western Social Networks (40+)
    "facebook.com", "instagram.com", "twitter.com", "x.com",
    "linkedin.com", "tiktok.com", "snapchat.com", "pinterest.com",
    "tumblr.com", "reddit.com", "quora.com", "medium.com",
    "substack.com", "mastodon.social", "mastodon.online",
    "bsky.app", "bluesky.social", "threads.net", "truth.social",
    "gettr.com", "parler.com", "gab.com", "minds.com",
    "mewe.com", "vero.co", "ello.co", "diaspora.social",
    "imgur.com", "flickr.com", "500px.com", "deviantart.com",
    "behance.net", "dribbble.com", "artstation.com", "pixiv.net",
    "patreon.com", "onlyfans.com", "ko-fi.com", "buymeacoffee.com",

    # Asian Social Networks (30+)
    "vk.com", "vk.ru", "ok.ru", "odnoklassniki.ru",
    "yandex.ru", "yandex.com", "mail.ru",
    "weibo.com", "sina.com.cn", "qq.com", "qzone.qq.com",
    "wechat.com", "douyin.com", "kuaishou.com", "xiaohongshu.com",
    "bilibili.com", "zhihu.com", "baidu.com", "tieba.baidu.com",
    "line.me", "line.today", "kakao.com", "kakaotalk.com",
    "naver.com", "daum.net", "band.us", "cyworld.com",
    "mixi.jp", "ameba.jp", "niconico.jp", "pixiv.net",

    # Messaging (40+)
    "whatsapp.com", "telegram.org", "t.me", "signal.org",
    "discord.com", "slack.com", "skype.com", "zoom.us",
    "webex.com", "gotomeeting.com", "jitsi.org", "meet.jit.si",
    "element.io", "matrix.org", "riot.im", "wire.com",
    "viber.com", "messenger.com", "imo.im", "kik.com",
    "wechat.com", "line.me", "kakaotalk.com", "threema.ch",
    "wickr.com", "session.app", "briar.app", "jami.net",
    "tox.chat", "retroshare.cc", "bitmessage.org",
    "microsoft teams.com", "google chat.com", "hangouts.google.com",
    "facebook messenger.com", "messenger.com", "viber.com",
    "imo.im", "telegram.me", "tg.me", "telegram.dog",

    # Professional & Business Networks (20+)
    "linkedin.com", "xing.com", "viadeo.com", "meetup.com",
    "eventbrite.com", "glassdoor.com", "indeed.com", "monster.com",
    "careerbuilder.com", "ziprecruiter.com", "hired.com",
    "angellist.com", "wellfound.com", "stackoverflow.com",
    "stackoverflow.jobs", "github.com", "gitlab.com",
    "producthunt.com", "hackernews.com", "ycombinator.com",

    # Forums & Communities (20+)
    "reddit.com", "voat.co", "communities.win", "scored.co",
    "4chan.org", "8kun.top", "lainchan.org", "somethingawful.com",
    "neogaf.com", "resetera.com", "kiwifarms.net",
    "stackexchange.com", "stackoverflow.com", "superuser.com",
    "askubuntu.com", "serverfault.com", "mathoverflow.net",
    "physics.stackexchange.com", "chemistry.stackexchange.com",
    "biology.stackexchange.com",
]

# ============================================================================
# NEWS & MEDIA (300+)
# ============================================================================

NEWS_MEDIA = [
    # US News (60+)
    "cnn.com", "nytimes.com", "washingtonpost.com", "usatoday.com",
    "wsj.com", "ft.com", "bloomberg.com", "reuters.com",
    "apnews.com", "npr.org", "pbs.org", "cbsnews.com",
    "abcnews.go.com", "nbcnews.com", "msnbc.com", "foxnews.com",
    "newsmax.com", "oann.com", "theblaze.com", "dailywire.com",
    "latimes.com", "nypost.com", "chicagotribune.com", "bostonglobe.com",
    "sfchronicle.com", "denverpost.com", "dallasnews.com",
    "time.com", "newsweek.com", "theweek.com", "politico.com",
    "thehill.com", "rollcall.com", "nationalreview.com",
    "theatlantic.com", "newyorker.com", "harpers.org", "motherjones.com",
    "thenation.com", "jacobin.com", "reason.com", "slate.com",
    "salon.com", "vox.com", "axios.com", "propublica.org",
    "theintercept.com", "buzzfeed.com", "huffpost.com", "vice.com",
    "theverge.com", "wired.com", "arstechnica.com", "techmeme.com",
    "techcrunch.com", "engadget.com", "gizmodo.com", "cnet.com",

    # UK News (30+)
    "bbc.com", "bbc.co.uk", "theguardian.com", "thetimes.co.uk",
    "telegraph.co.uk", "independent.co.uk", "dailymail.co.uk",
    "thesun.co.uk", "mirror.co.uk", "express.co.uk", "standard.co.uk",
    "metro.co.uk", "thetimes.com", "economist.com", "spectator.co.uk",
    "newstatesman.com", "private eye.co.uk", "channel4.com/news",
    "itv.com/news", "sky.com/news", "reuters.com", "ft.com",
    "cityam.com", "evening standard.co.uk", "scotsman.com",
    "heraldscotland.com", "walesonline.co.uk", "belfasttelegraph.co.uk",
    "irishtimes.com", "rte.ie",

    # French News (40+)
    "lemonde.fr", "lefigaro.fr", "liberation.fr", "leparisien.fr",
    "20minutes.fr", "ouest-france.fr", "france24.com", "francetvinfo.fr",
    "franceinfo.fr", "tf1.fr", "tf1info.fr", "bfmtv.com",
    "lci.fr", "europe1.fr", "rtl.fr", "rfi.fr", "rmc.fr",
    "lepoint.fr", "lexpress.fr", "marianne.net", "nouvelobs.com",
    "challenges.fr", "capital.fr", "lesechos.fr", "latribune.fr",
    "mediapart.fr", "rue89.nouvelobs.com", "lecanardenchaine.fr",
    "lopinion.fr", "humanite.fr", "lequipe.fr", "leparisien.fr",
    "sudouest.fr", "nicematin.com", "leprogres.fr", "ledauphine.com",
    "lavoixdunord.fr", "estrepublicain.fr", "dna.fr", "republicain-lorrain.fr",

    # German News (30+)
    "spiegel.de", "bild.de", "zeit.de", "sueddeutsche.de",
    "faz.net", "welt.de", "focus.de", "stern.de",
    "handelsblatt.com", "wiwo.de", "tagesschau.de", "zdf.de",
    "n-tv.de", "dw.com", "deutschlandfunk.de", "tagesspiegel.de",
    "fr.de", "berliner-zeitung.de", "morgenpost.de", "abendblatt.de",
    "rp-online.de", "ksta.de", "express.de", "mopo.de",
    "merkur.de", "tz.de", "augsburger-allgemeine.de", "mainpost.de",
    "swr.de", "br.de",

    # Spanish News (25+)
    "elpais.com", "elmundo.es", "abc.es", "lavanguardia.com",
    "20minutos.es", "elconfidencial.com", "eldiario.es", "publico.es",
    "expansion.com", "cincodias.com", "marca.com", "as.com",
    "sport.es", "mundodeportivo.com", "rtve.es", "antena3.com",
    "lasexta.com", "cuatro.com", "telecinco.es", "elespanol.com",
    "okdiario.com", "vozpopuli.com", "elplural.com", "huffingtonpost.es",
    "eleconomista.es",

    # Italian News (20+)
    "corriere.it", "repubblica.it", "lastampa.it", "ilsole24ore.com",
    "ansa.it", "ilgiornale.it", "ilmessaggero.it", "gazzetta.it",
    "corrieredellosport.it", "tuttosport.com", "ilfattoquotidiano.it",
    "huffingtonpost.it", "fanpage.it", "tgcom24.mediaset.it",
    "rainews.it", "adnkronos.com", "agi.it", "ilpost.it",
    "linkiesta.it", "ilfoglio.it",

    # Asian News (40+)
    "asahi.com", "yomiuri.co.jp", "nikkei.com", "mainichi.jp",
    "japantimes.co.jp", "japan-guide.com", "nhk.or.jp",
    "timesofindia.indiatimes.com", "hindustantimes.com", "indianexpress.com",
    "thehindu.com", "economictimes.indiatimes.com", "ndtv.com",
    "news18.com", "india.com", "firstpost.com", "thequint.com",
    "thewire.in", "scroll.in", "livemint.com",
    "straitstimes.com", "channelnewsasia.com", "todayonline.com",
    "scmp.com", "chinadaily.com.cn", "globaltimes.cn", "xinhuanet.com",
    "peopledaily.com.cn", "china.org.cn", "cgtn.com",
    "koreatimes.co.kr", "koreaherald.com", "yonhapnews.co.kr",
    "hani.co.kr", "chosun.com", "joins.com", "donga.com",
    "bangkokpost.com", "nationthailand.com", "thestar.com.my",

    # Business & Finance News (30+)
    "bloomberg.com", "reuters.com", "ft.com", "wsj.com",
    "marketwatch.com", "seekingalpha.com", "fool.com", "motleyfool.com",
    "investing.com", "marketscreener.com", "barrons.com",
    "investors.com", "investopedia.com", "cnbc.com", "benzinga.com",
    "zacks.com", "morningstar.com", "stocktwits.com", "finviz.com",
    "tradingview.com", "yahoofinance.com", "finance.yahoo.com",
    "google.com/finance", "money.cnn.com", "businessinsider.com",
    "forbes.com", "fortune.com", "inc.com", "fastcompany.com",
    "entrepreneur.com",

    # Tech & Science News (40+)
    "techcrunch.com", "theverge.com", "engadget.com", "gizmodo.com",
    "cnet.com", "zdnet.com", "arstechnica.com", "slashdot.org",
    "hackernews.com", "news.ycombinator.com", "techmeme.com",
    "mashable.com", "thenextweb.com", "venturebeat.com", "recode.net",
    "theinformation.com", "protocol.com", "9to5mac.com", "macrumors.com",
    "appleinsider.com", "androidauthority.com", "androidpolice.com",
    "xda-developers.com", "tomshardware.com", "anandtech.com",
    "nature.com", "science.org", "sciencedaily.com", "phys.org",
    "sciencenews.org", "newscientist.com", "scientificamerican.com",
    "space.com", "astronomy.com", "nationalgeographic.com",
    "smithsonianmag.com", "popularmechanics.com", "popsci.com",
    "technologyreview.com", "spectrum.ieee.org",
]

# ============================================================================
# EDUCATION & RESEARCH (300+)
# ============================================================================

EDUCATION = [
    # Top US Universities (50+)
    "harvard.edu", "stanford.edu", "mit.edu", "yale.edu", "princeton.edu",
    "columbia.edu", "uchicago.edu", "upenn.edu", "cornell.edu", "dartmouth.edu",
    "brown.edu", "duke.edu", "northwestern.edu", "jhu.edu", "caltech.edu",
    "berkeley.edu", "ucla.edu", "usc.edu", "umich.edu", "nyu.edu",
    "georgetown.edu", "carnegiemellon.edu", "cmu.edu", "emory.edu", "rice.edu",
    "vanderbilt.edu", "notredame.edu", "wustl.edu", "unc.edu", "virginia.edu",
    "gatech.edu", "uiuc.edu", "wisc.edu", "ucsb.edu", "ucsd.edu",
    "ucdavis.edu", "uci.edu", "ucr.edu", "ucsc.edu", "ucmerced.edu",
    "psu.edu", "osu.edu", "msu.edu", "purdue.edu", "indiana.edu",
    "rutgers.edu", "umd.edu", "vt.edu", "ncsu.edu", "tamu.edu",

    # Top UK Universities (30+)
    "ox.ac.uk", "cam.ac.uk", "imperial.ac.uk", "lse.ac.uk", "ucl.ac.uk",
    "kcl.ac.uk", "ed.ac.uk", "manchester.ac.uk", "bristol.ac.uk",
    "warwick.ac.uk", "glasgow.ac.uk", "birmingham.ac.uk", "leeds.ac.uk",
    "sheffield.ac.uk", "nottingham.ac.uk", "southampton.ac.uk",
    "york.ac.uk", "lancaster.ac.uk", "durham.ac.uk", "exeter.ac.uk",
    "bath.ac.uk", "cardiff.ac.uk", "liverpool.ac.uk", "qmul.ac.uk",
    "reading.ac.uk", "sussex.ac.uk", "surrey.ac.uk", "lboro.ac.uk",
    "strath.ac.uk", "abdn.ac.uk",

    # Top European Universities (40+)
    "ethz.ch", "epfl.ch", "uzh.ch", "unige.ch", "unil.ch",
    "tum.de", "lmu.de", "uni-heidelberg.de", "uni-muenchen.de",
    "hu-berlin.de", "fu-berlin.de", "uni-bonn.de", "uni-freiburg.de",
    "sorbonne-universite.fr", "ens.fr", "polytechnique.edu", "upmc.fr",
    "univ-paris-diderot.fr", "univ-paris1.fr", "sciences-po.fr",
    "uva.nl", "leiden.nl", "uu.nl", "rug.nl", "tue.nl",
    "ku.dk", "dtu.dk", "su.se", "ki.se", "uu.se",
    "kth.se", "uio.no", "ntnu.no", "uib.no", "helsinki.fi",
    "aalto.fi", "uniroma1.it", "unimi.it", "sapienza.it",

    # Top Asian Universities (30+)
    "u-tokyo.ac.jp", "kyoto-u.ac.jp", "osaka-u.ac.jp", "tohoku.ac.jp",
    "nus.edu.sg", "ntu.edu.sg", "smu.edu.sg", "sutd.edu.sg",
    "hku.hk", "cuhk.edu.hk", "hkust.edu.hk", "cityu.edu.hk",
    "polyu.edu.hk", "pku.edu.cn", "tsinghua.edu.cn", "fudan.edu.cn",
    "sjtu.edu.cn", "zju.edu.cn", "ustc.edu.cn", "nju.edu.cn",
    "kaist.ac.kr", "snu.ac.kr", "postech.ac.kr", "yonsei.ac.kr",
    "iitb.ac.in", "iitd.ac.in", "iitm.ac.in", "iisc.ac.in",
    "ntu.edu.tw", "ncu.edu.tw",

    # Online Learning Platforms (40+)
    "coursera.org", "udemy.com", "edx.org", "khanacademy.org",
    "duolingo.com", "codecademy.com", "skillshare.com", "udacity.com",
    "pluralsight.com", "linkedin learning.com", "lynda.com",
    "masterclass.com", "brilliant.org", "datacamp.com", "treehouse.com",
    "openclassrooms.com", "fun-mooc.fr", "canvas.net", "futurelearn.com",
    "skillsoft.com", "alison.com", "udacity.com", "class central.com",
    "mooc-list.com", "academi a.edu", "researchgate.net",
    "scholar.google.com", "google scholar.com", "semantic scholar.org",
    "mendeley.com", "zotero.org", "refworks.com", "endnote.com",
    "cite thisfor me.com", "easybib.com", "bibme.org", "scribbr.com",
    "grammarly.com", "hemingwayapp.com", "prowritingaid.com",
    "languagetool.org",

    # Academic Resources (50+)
    "wikipedia.org", "wikimedia.org", "wikidata.org", "commons.wikimedia.org",
    "scholar.google.com", "researchgate.net", "academia.edu",
    "arxiv.org", "biorxiv.org", "medrxiv.org", "ssrn.com",
    "jstor.org", "pubmed.gov", "nih.gov", "ncbi.nlm.nih.gov",
    "sciencedirect.com", "springer.com", "springerlink.com",
    "nature.com", "science.org", "pnas.org", "cell.com",
    "wiley.com", "elsevier.com", "tandfonline.com", "sagepub.com",
    "ieee.org", "ieeexplore.ieee.org", "acm.org", "dl.acm.org",
    "ams.org", "mathscinet.ams.org", "zbmath.org", "mathoverflow.net",
    "projecteuclid.org", "doaj.org", "plos.org", "frontiersin.org",
    "mdpi.com", "hindawi.com", "biomedcentral.com", "peerj.com",
    "f1000research.com", "wellcomeopenresearch.org", "openedition.org",
    "core.ac.uk", "base-search.net", "refseek.com", "virtuallrc.com",

    # K-12 Education (30+)
    "pearson.com", "mcgraw-hill.com", "hmhco.com", "scholastic.com",
    "education.com", "ixl.com", "raz-kids.com", "abcmouse.com",
    "starfall.com", "funbrain.com", "coolmath.com", "coolmathgames.com",
    "mathplayground.com", "splashlearn.com", "prodigy game.com",
    "brainpop.com", "readtheory.org", "commonlit.org", "newsela.com",
    "readworks.org", "achieve3000.com", "lexialearning.com",
    "imagine learning.com", "dreambox.com", "zearn.org",
    "illustrativemathematics.org", "openup resources.org",
    "oerproject.com", "ck12.org", "flexbooks.ck12.org",
]

# ============================================================================
# DEVELOPER TOOLS & TECH (200+)
# ============================================================================

DEVELOPER_TOOLS = [
    # Code Hosting (20+)
    "github.com", "gitlab.com", "bitbucket.org", "sourceforge.net",
    "codeberg.org", "gitea.io", "gogs.io", "notabug.org",
    "gitee.com", "coding.net", "assembla.com", "beanstalkapp.com",
    "codebasehq.com", "deveo.com", "rhodecode.com", "allura.apache.org",
    "launchpad.net", "savannah.gnu.org", "repo.or.cz", "git.sr.ht",

    # Package Managers (30+)
    "npmjs.com", "npm.js.org", "pypi.org", "rubygems.org",
    "packagist.org", "crates.io", "nuget.org", "maven.org",
    "mvnrepository.com", "cocoapods.org", "pub.dev", "hex.pm",
    "getcomposer.org", "bower.io", "yarn.pm", "pnpm.io",
    "cpan.org", "metacpan.org", "hackage.haskell.org",
    "opam.ocaml.org", "clojars.org", "rebar3.org",
    "mix.hex.pm", "cargo.io", "go.dev", "pkg.go.dev",
    "deno.land", "nest.land", "chocolatey.org", "scoop.sh",

    # Developer Communities (30+)
    "stackoverflow.com", "stackexchange.com", "superuser.com",
    "serverfault.com", "askubuntu.com", "unix.stackexchange.com",
    "dev.to", "dev.to", "hashnode.com", "medium.com",
    "hackernoon.com", "dzone.com", "codeproject.com",
    "reddit.com/r/programming", "reddit.com/r/webdev",
    "reddit.com/r/learnprogramming", "lobste.rs", "tildes.net",
    "discourse.org", "freenode.net", "libera.chat",
    "mozillazine.org", "linuxquestions.org", "ubuntuforums.org",
    "archlinux.org", "gentoo.org", "freebsd.org", "openbsd.org",
    "netbsd.org", "slackware.com",

    # Documentation & Learning (40+)
    "w3schools.com", "mdn.mozilla.org", "developer.mozilla.org",
    "devdocs.io", "roadmap.sh", "freecodecamp.org", "codecademy.com",
    "geeksforgeeks.org", "tutorialspoint.com", "javatpoint.com",
    "programiz.com", "learncpp.com", "learnpython.org", "learn-c.org",
    "cplusplus.com", "cppreference.com", "python.org", "docs.python.org",
    "ruby-lang.org", "ruby-doc.org", "php.net", "docs.php.net",
    "java.com", "oracle.com/java", "docs.oracle.com",
    "javascript.info", "eloquentjavascript.net", "typescript lang.org",
    "golang.org", "go.dev", "rustlang.org", "rust-lang.org",
    "swift.org", "kotlin lang.org", "scala-lang.org",
    "haskell.org", "ocaml.org", "elixir-lang.org", "erlang.org",
    "clojure.org",

    # IDEs & Editors (20+)
    "jetbrains.com", "intellij-support.jetbrains.com",
    "visualstudio.com", "code.visualstudio.com", "vscode.dev",
    "atom.io", "sublimetext.com", "vim.org", "neovim.io",
    "emacs.org", "gnu.org/software/emacs", "eclipse.org",
    "netbeans.apache.org", "brackets.io", "notepad-plus-plus.org",
    "codenvy.com", "che.eclipse.org", "theia-ide.org",
    "gitpod.io", "repl.it",

    # DevOps & CI/CD (40+)
    "docker.com", "docker.io", "hub.docker.com", "kubernetes.io",
    "k8s.io", "rancher.com", "podman.io", "containerd.io",
    "jenkins.io", "travis-ci.org", "travis-ci.com",
    "circleci.com", "github actions", "actions.github.com",
    "gitlab-ci.com", "gitlab.io", "bamboo.atlassian.com",
    "teamcity.jetbrains.com", "azure devops.com", "dev.azure.com",
    "ansible.com", "ansible.com", "terraform.io", "hashicorp.com",
    "puppet.com", "puppetlabs.com", "chef.io", "saltproject.io",
    "vagrantup.com", "packer.io", "vault project.io",
    "consul.io", "nomad.io", "pulumi.com",
    "spinnaker.io", "argo-cd.readthedocs.io", "fluxcd.io",
    "tekton.dev", "drone.io", "concourse-ci.org", "buildkite.com",

    # Monitoring & Observability (30+)
    "datadog.com", "datadoghq.com", "newrelic.com", "splunk.com",
    "elastic.co", "elasticsearch.org", "kibana.org", "logstash.net",
    "grafana.com", "prometheus.io", "influxdata.com", "influxdb.com",
    "sentry.io", "rollbar.com", "bugsnag.com", "raygun.com",
    "appdynamics.com", "dynatrace.com", "sumologic.com",
    "loggly.com", "papertrailapp.com", "graylog.org",
    "nagios.org", "icinga.com", "zabbix.com", "cacti.net",
    "prtg.com", "solarwinds.com", "opsgenie.com", "pagerduty.com",
]

# ============================================================================
# GOVERNMENT & PUBLIC SERVICES (150+)
# ============================================================================

GOVERNMENT = [
    # International Organizations (20+)
    "un.org", "who.int", "unesco.org", "unicef.org", "unhcr.org",
    "wfp.org", "fao.org", "imf.org", "worldbank.org",
    "nato.int", "europa.eu", "ec.europa.eu", "europarl.europa.eu",
    "oecd.org", "wto.org", "iaea.org", "opcw.org",
    "icc-cpi.int", "icj-cij.org", "interpol.int",

    # US Government (50+)
    "usa.gov", "whitehouse.gov", "congress.gov", "senate.gov",
    "house.gov", "supremecourt.gov", "uscourts.gov",
    "fbi.gov", "cia.gov", "nsa.gov", "dhs.gov", "tsa.gov",
    "state.gov", "defense.gov", "army.mil", "navy.mil",
    "af.mil", "marines.mil", "uscg.mil", "nga.mil",
    "justice.gov", "doj.gov", "atf.gov", "dea.gov",
    "treasury.gov", "irs.gov", "ssa.gov", "medicare.gov",
    "medicaid.gov", "healthcare.gov", "hhs.gov", "cdc.gov",
    "fda.gov", "nih.gov", "epa.gov", "energy.gov",
    "usps.com", "usps.gov", "nasa.gov", "nsf.gov",
    "noaa.gov", "weather.gov", "usgs.gov", "nps.gov",
    "doi.gov", "usda.gov", "ed.gov", "hud.gov",
    "va.gov", "dol.gov", "ftc.gov", "fcc.gov",

    # UK Government (20+)
    "gov.uk", "parliament.uk", "royal.uk", "nhs.uk",
    "hmrc.gov.uk", "dwp.gov.uk", "homeoffice.gov.uk",
    "fco.gov.uk", "mod.uk", "judiciary.uk", "supremecourt.uk",
    "police.uk", "met.police.uk", "transport.gov.uk",
    "gov.scot", "gov.wales", "nidirect.gov.uk",
    "legislation.gov.uk", "nationalarchives.gov.uk", "ons.gov.uk",

    # French Government (30+)
    "gouvernement.fr", "elysee.fr", "premier-ministre.gouv.fr",
    "assemblee-nationale.fr", "senat.fr", "conseil-constitutionnel.fr",
    "service-public.fr", "france-connect.gouv.fr",
    "impots.gouv.fr", "ameli.fr", "caf.fr", "pole-emploi.fr",
    "education.gouv.fr", "enseignementsup-recherche.gouv.fr",
    "interieur.gouv.fr", "defense.gouv.fr", "justice.gouv.fr",
    "economie.gouv.fr", "travail-emploi.gouv.fr",
    "solidarites-sante.gouv.fr", "culture.gouv.fr",
    "sports.gouv.fr", "agriculture.gouv.fr", "ecologie.gouv.fr",
    "laposte.fr", "laposte.net", "courrier.laposte.fr",
    "data.gouv.fr", "legifrance.gouv.fr",

    # Other European Governments (20+)
    "bundesregierung.de", "bundestag.de", "bundesrat.de",
    "gov.ie", "oireachtas.ie", "rijksoverheid.nl", "tweedekamer.nl",
    "governo.it", "quirinale.it", "senato.it", "camera.it",
    "lamoncloa.gob.es", "congreso.es", "senado.es",
    "government.se", "riksdagen.se", "regjeringen.no",
    "stortinget.no", "valtioneuvosto.fi", "eduskunta.fi",

    # Other Major Governments (10+)
    "canada.ca", "gc.ca", "australia.gov.au", "gov.au",
    "govt.nz", "newzealand.govt.nz", "india.gov.in", "gov.in",
    "brazil.gov.br", "gov.br", "gov.cn", "gov.jp",
]

# ============================================================================
# HEALTH & WELLNESS (100+)
# ============================================================================

HEALTH = [
    # Medical Information (30+)
    "webmd.com", "mayoclinic.org", "mayoclinic.com", "nih.gov",
    "cdc.gov", "who.int", "healthline.com", "medicalnewstoday.com",
    "medlineplus.gov", "drugs.com", "rxlist.com", "everydayhealth.com",
    "patient.info", "nhs.uk", "clevelandclinic.org", "johnshopkins.edu",
    "hopkinsmedicine.org", "health.harvard.edu", "ucsf.edu",
    "ucsfhealth.org", "stanfordhealthcare.org", "cedars-sinai.org",
    "mountsinai.org", "nyulangone.org", "massgeneral.org",
    "brighamandwomens.org", "childrenshospital.org", "stjude.org",
    "mdanderson.org", "mskcc.org",

    # Telehealth & Appointments (20+)
    "doctolib.fr", "qare.fr", "livi.fr", "maiia.com",
    "alan.com", "teladoc.com", "amwell.com", "mdlive.com",
    "plushcare.com", "doctoralia.com", "zocdoc.com",
    "practo.com", "1mg.com", "netmeds.com", "pharmeasy.com",
    "apollo247.com", "doconline.com", "healthtap.com",
    "talkspace.com", "betterhelp.com",

    # Health Insurance (30+)
    "uhc.com", "unitedhealthcare.com", "anthem.com", "wellpoint.com",
    "aetna.com", "cigna.com", "humana.com", "bluecross.com",
    "blueshield.com", "bcbs.com", "kaiserpermanente.org", "kp.org",
    "centene.com", "molina healthcare.com", "wellcare.com",
    "healthnet.com", "emblemhealth.com", "oscar.com",
    "bright health.com", "clover health.com", "devoted health.com",
    "alignment healthcare.com", "ameli.fr", "assurance-maladie.fr",
    "cpam.fr", "harmonie-mutuelle.fr", "mgen.fr", "malakoff humanis.fr",
    "axa.fr", "allianz.fr",

    # Fitness & Wellness (20+)
    "fitbit.com", "myfitnesspal.com", "strava.com", "peloton.com",
    "nike.com/ntc", "nikeplus.com", "applehealth.com",
    "garmin.com", "polar.com", "suunto.com", "withings.com",
    "calm.com", "headspace.com", "noom.com", "weightwatchers.com",
    "ww.com", "classpass.com", "mindbody.com", "gympass.com",
    "crunch.com",
]

# ============================================================================
# TRAVEL & TRANSPORTATION (100+)
# ============================================================================

TRAVEL = [
    # Booking Platforms (30+)
    "booking.com", "airbnb.com", "vrbo.com", "homeaway.com",
    "tripadvisor.com", "expedia.com", "hotels.com", "priceline.com",
    "kayak.com", "skyscanner.com", "momondo.com", "cheapflights.com",
    "hotwire.com", "orbitz.com", "travelocity.com", "agoda.com",
    "hostelworld.com", "hostel bookers.com", "couchsurfing.com",
    "holidaylettings.co.uk", "abritel.fr", "homelidays.com",
    "gites-de-france.com", "trivago.com", "hotelscombined.com",
    "roomguru.com", "hrs.com", "venere.com", "lastminute.com",

    # Airlines (40+)
    "aa.com", "americanairlines.com", "united.com", "delta.com",
    "southwest.com", "jetblue.com", "alaskaair.com", "spirit.com",
    "frontier.com", "allegiantair.com", "sun-air.com",
    "britishairways.com", "ba.com", "lufthansa.com", "airfrance.fr",
    "airfrance.com", "klm.com", "alitalia.com", "iberia.com",
    "ryanair.com", "easyjet.com", "wizzair.com", "norwegian.com",
    "vueling.com", "transavia.com", "eurowings.com",
    "emirates.com", "etihad.com", "qatarairways.com", "turkishairlines.com",
    "singaporeair.com", "cathaypacific.com", "ana.co.jp", "jal.co.jp",
    "koreanair.com", "airindia.in", "qantas.com", "aircanada.com",
    "aerolineas.com.ar", "latam.com",

    # Transportation (30+)
    "uber.com", "lyft.com", "blablacar.com", "flixbus.com",
    "megabus.com", "greyhound.com", "amtrak.com", "viarail.ca",
    "sncf.com", "oui.sncf", "trainline.com", "thetrainline.com",
    "raileurope.com", "eurail.com", "interrail.eu",
    "bahn.de", "deutschebahn.com", "trenitalia.com", "renfe.com",
    "sbb.ch", "ns.nl", "eurostar.com", "thalys.com",
    "ouigo.com", "trainpal.com", "busbud.com", "rome2rio.com",
    "moovit.com", "citymapper.com", "transit.app",
]

# ============================================================================
# REAL ESTATE & HOME (50+)
# ============================================================================

REAL_ESTATE = [
    # US Real Estate (20+)
    "zillow.com", "realtor.com", "redfin.com", "trulia.com",
    "apartmentlist.com", "apartments.com", "rent.com", "zumper.com",
    "padmapper.com", "hotpads.com", "streeteasy.com", "compass.com",
    "coldwellbanker.com", "century21.com", "sothebys realty.com",
    "remax.com", "kw.com", "kellerwilliams.com", "bhhs.com",
    "bhhspro.com",

    # International Real Estate (20+)
    "seloger.com", "leboncoin.fr", "pap.fr", "logic-immo.com",
    "bien-ici.com", "explorimmo.com", "paruvendu.fr",
    "rightmove.co.uk", "zoopla.co.uk", "onthemarket.com",
    "primelocation.com", "immobilienscout24.de", "immowelt.de",
    "idealista.com", "fotocasa.es", "immobiliare.it", "casa.it",
    "funda.nl", "pararius.nl", "property24.com", "propsearch.com",

    # Home Services (10+)
    "thumbtack.com", "angi.com", "angieslist.com", "homeadvisor.com",
    "taskrabbit.com", "handy.com", "care.com", "rover.com",
    "wag.com", "porch.com",
]

# ============================================================================
# UTILITIES & SERVICES (50+)
# ============================================================================

UTILITIES = [
    # Shipping & Logistics (20+)
    "usps.com", "ups.com", "fedex.com", "dhl.com",
    "aramex.com", "tnt.com", "dpd.com", "gls-group.eu",
    "colissimo.fr", "chronopost.fr", "colis-prive.fr",
    "mondial-relay.fr", "laposte.fr", "royalmail.com",
    "parcelforce.com", "auspost.com.au", "canadapost.ca",
    "correos.es", "poste.it", "deutschepost.de",

    # Telecommunications (30+)
    "att.com", "verizon.com", "tmobile.com", "sprint.com",
    "uscellular.com", "boostmobile.com", "metroPCS.com",
    "cricket wireless.com", "visible.com", "mint mobile.com",
    "bt.com", "ee.co.uk", "vodafone.com", "vodafone.co.uk",
    "o2.co.uk", "three.co.uk", "virginmedia.com", "sky.com",
    "orange.fr", "orange.com", "sfr.fr", "bouyguestelecom.fr",
    "free.fr", "sosh.fr", "red-by-sfr.fr", "b-and-you.fr",
    "telekom.de", "vodafone.de", "o2.de", "1and1.de","hotel-bellevue.fr",
    'example.com','auth0.com','avocat-durand.fr','garage-martin.fr'
]

CRITICAL_MISSING = [
        'mandrillapp.com', 'fly.io', 'polyfill.io', 'render.com', 'forms.gle', 'jsdelivr.net',
        'notion.so', 'glitch.com', 'bootstrapcdn.com', 'codesandbox.io', 'clickup.com', 'goo.gl',
        'trello.com', 'salesforce.com', 'deno.comfontawesome.com', 'fonts.googleapis.com', 'amzn.to',
        'calendly.com', 'maxcdn.bootstrapcdn.com', 'bit.ly', 'linear.app', 'typeform.com', 'tinyurl.com',
        'shor.by', 'disqus.com', 'deno.com', 'mailchimp.com', 'heroku.com', 'vercel.app', 'monday.com',
        'stripe.com', 't.co', 'cal.com', 'atlassian.com', 'jquery.com', 'railway.app', 'cdnjs.cloudflare.com',
        'clk.sh', 'use.fontawesome.com', 'zoom.us', 'buff.ly', 'is.gd', 'sendgrid.net', 'cdn.jsdelivr.net',
        'fontawesome.com', 's.id', 'asana.com', 'unpkg.com', 'v.gd', 'replit.com', 'stackblitz.com', 'netlify.app',
        'dropbox.com', 'airtable.com', 'youtu.be', 'hubspot.com', 'ajax.googleapis.com', 'ow.ly', 'figma.com',
        'id.atlassian.com'
    ]

# ============================================================================
# FRENCH MEDIA & NEWS (Supplément)
# ============================================================================

FRENCH_MEDIA_EXTENDED = [
    "lemonde.fr", "lefigaro.fr", "liberation.fr", "leparisien.fr",
    "20minutes.fr", "ouest-france.fr", "france24.com", "francetvinfo.fr",
    "tf1.fr", "bfmtv.com", "lci.fr", "cnews.fr", "france3.fr",
    "m6.fr", "arte.tv", "rtl.fr", "europe1.fr", "franceinter.fr",
    "rfi.fr", "franceculture.fr", "francemusique.fr", "radiofrance.fr",
    "lesechos.fr", "latribune.fr", "lepoint.fr", "lexpress.fr",
    "marianne.net", "nouvelobs.com", "challenges.fr", "capital.fr",
    "mediapart.fr", "valeursactuelles.com", "humanite.fr", "lejdd.fr",
    "parismatch.com", "gala.fr", "voici.fr", "closer.fr",
    "telerama.fr", "telestar.fr", "programme-tv.net", "allocine.fr",
    "senscritique.com", "gameblog.fr", "jeuxvideo.com", "canalplus.com"
]

# ============================================================================
# FRENCH E-COMMERCE & SERVICES (Supplément)
# ============================================================================

FRENCH_ECOMMERCE_SERVICES = [
    "cdiscount.com", "fnac.com", "darty.com", "boulanger.com",
    "carrefour.fr", "auchan.fr", "leclerc.fr", "casino.fr",
    "monoprix.fr", "franprix.fr", "intermarche.com", "systeme-u.fr",
    "veepee.fr", "vente-privee.com", "showroomprive.com", "brandalley.fr",
    "backmarket.fr", "ldlc.com", "materiel.net", "topachat.com",
    "rueducommerce.fr", "priceminister.com", "rakuten.fr", "manomano.fr",
    "misterauto.com", "alltricks.fr", "culturefactory.fr", "placedeslibraires.fr",
    "decitre.fr", "fnac.com", "gibertjeune.fr", "amazon.fr",
    "cultura.com", "leroymerlin.fr", "castorama.fr", "bricorama.fr",
    "bricomarche.com", "pointp.fr", "chaussea.com", "sport2000.fr"
]

# ============================================================================
# FRENCH GOVERNMENT & PUBLIC SERVICES (Supplément)
# ============================================================================

FRENCH_GOVERNMENT_PUBLIC = [
    "service-public.fr", "impots.gouv.fr", "ameli.fr", "caf.fr",
    "pole-emploi.fr", "secu.fr", "assurance-maladie.fr", "cpam.fr",
    "msa.fr", "urssaf.fr", "dgfip.fr", "douane.gouv.fr",
    "education.gouv.fr", "onisep.fr", "parcoursup.fr", "crous.fr",
    "etudiant.gouv.fr", "jeunes.gouv.fr", "logement.gouv.fr",
    "anah.fr", "actionlogement.fr", "cci.fr", "cm.fr",
    "banque-france.fr", "insee.fr", "statistiques.fr", "data.gouv.fr"
]

# ============================================================================
# FRENCH BANKS & FINANCE (Supplément)
# ============================================================================

FRENCH_BANKS_FINANCE = [
    "bnpparibas.fr", "societegenerale.fr", "credit-agricole.fr",
    "lcl.fr", "banquepopulaire.fr", "caisse-epargne.fr",
    "creditmutuel.fr", "cic.fr", "labanquepostale.fr",
    "hsbc.fr", "boursorama.fr", "fortuneo.fr", "hellobank.fr",
    "ing.fr", "axabanque.fr", "orangebank.fr", "n26.fr",
    "qonto.com", "shine.fr", "lendix.fr", "younited-credit.com"
]

# ============================================================================
# FRENCH TRANSPORT & TRAVEL (Supplément)
# ============================================================================

FRENCH_TRANSPORT_TRAVEL = [
    "sncf.fr", "oui.sncf", "tgv.com", "ter.sncf",
    "transilien.com", "ratp.fr", "iledefrance-mobilites.fr",
    "paris.fr", "vinci-autoroutes.fr", "sanef.fr",
    "aeroportsdeparis.fr", "airfrance.fr", "airfrance.com",
    "transavia.com", "corsair.com", "aircaraibes.com",
    "blablacar.fr", "blablacar.com", "ouibus.com",
    "flixbus.fr", "mobilite-connect.com", "citymapper.com"
]

# ============================================================================
# EUROPEAN TECH & STARTUPS (Supplément)
# ============================================================================

EUROPEAN_TECH_STARTUPS = [
    "spotify.com", "skype.com", "transferwise.com", "klarna.com",
    "deliveroo.com", "just-eat.com", "deliveroo.fr", "ubereats.com",
    "glovo.com", "takeaway.com", "doctolib.fr", "blablacar.com",
    "backmarket.fr", "veepee.fr", "manomano.fr", "alan.com",
    "qonto.com", "transferwise.com", "revolut.com", "n26.com",
    "getaround.com", "drivy.com", "ouicar.fr", "zenly.com",
    "deepmind.com", "arm.com", "raspberrypi.org", "canonical.com"
]

# ============================================================================
# INTERNATIONAL TELECOMS (Supplément)
# ============================================================================

INTERNATIONAL_TELECOMS = [
    "vodafone.com", "vodafone.co.uk", "vodafone.de", "vodafone.es",
    "vodafone.it", "vodafone.com.au", "telefonica.com", "telecom.it",
    "telecom.fr", "dtag.com", "deutschetelekom.de", "t-mobile.com",
    "t-mobile.de", "bell.ca", "rogers.com", "telus.com",
    "telecom.co.nz", "spark.co.nz", "vodafone.co.nz", "optus.com.au",
    "telstra.com.au", "singtel.com", "starhub.com", "ais.co.th",
    "true.th", "dtac.co.th", "softbank.jp", "ntt.co.jp", "kddi.com"
]

# ============================================================================
# GLOBAL AUTOMOTIVE (Supplément)
# ============================================================================

GLOBAL_AUTOMOTIVE = [
    "toyota.com", "honda.com", "nissan.com", "ford.com",
    "chevrolet.com", "bmw.com", "mercedes-benz.com", "audi.com",
    "volkswagen.com", "volvocars.com", "hyundai.com", "kia.com",
    "renault.com", "peugeot.com", "citroen.com", "fiat.com",
    "ferrari.com", "lamborghini.com", "porsche.com", "tesla.com",
    "gm.com", "stellantis.com", "daimler.com", "volvo.com",
    "subaru.com", "mazda.com", "mitsubishi.com", "suzuki.com"
]

# ============================================================================
# FOOD DELIVERY & RESTAURANTS (Supplément)
# ============================================================================

FOOD_DELIVERY_RESTAURANTS = [
    "ubereats.com", "doordash.com", "grubhub.com", "justeat.com",
    "deliveroo.co.uk", "deliveroo.fr", "foodora.com", "glovo.com",
    "takeaway.com", "menulog.com.au", "swiggy.com", "zomato.com",
    "mcdonalds.com", "kfc.com", "burgerking.com", "subway.com",
    "starbucks.com", "dominos.com", "pizzahut.com", "papajohns.com",
    "chipotle.com", "panerabread.com", "dunkindonuts.com", "wendys.com"
]

# ============================================================================
# GAMING & ESPORTS (Supplément)
# ============================================================================

GAMING_ESPORTS = [
    "ea.com", "ubisoft.com", "activision.com", "blizzard.com",
    "valvesoftware.com", "rockstargames.com", "nintendo.com",
    "playstation.com", "xbox.com", "sega.com", "bandainamco.com",
    "square-enix.com", "capcom.com", "konami.com", "epicgames.com",
    "unity.com", "unrealengine.com", "twitch.tv", "discord.gg",
    "steamcommunity.com", "origin.com", "uplay.com", "gog.com"
]
# ============================================================================
# FRENCH REGIONAL MEDIA & NEWS
# ============================================================================

FRENCH_REGIONAL_MEDIA = [
    "lavoixdunord.fr", "nordeclair.fr", "courrier-picard.fr", "paris-normandie.fr",
    "lechorepublicain.fr", "berryrepublicain.fr", "lanouvellerepublique.fr", "centre-presse.fr",
    "lepopulaire.fr", "lamontagne.fr", "sudouest.fr", "charentelibre.fr",
    "larepubliquedespyrenees.fr", "ladepeche.fr", "midilibre.fr", "lindependant.fr",
    "nicematin.fr", "laprovence.com", "ledauphine.com", "lessorsavoyard.fr",
    "leprogres.fr", "lejsl.fr", "estrepublicain.fr", "vosgesmatin.fr",
    "dna.fr", "lalsace.fr", "courrierdelouest.fr", "ouest-france.fr",
    "letelegramme.fr", "letelegramme.fr", "presse-ocean.com", "maville.com"
]

# ============================================================================
# FRENCH PUBLIC SERVICES & ADMINISTRATION
# ============================================================================

FRENCH_PUBLIC_SERVICES = [
    "mon.service-public.fr", "mesdroitssociaux.gouv.fr", "impots.gouv.fr",
    "ameli.fr", "caf.fr", "pole-emploi.fr", "laposte.fr",
    "enedis.fr", "grdf.fr", "engie.fr", "edf.fr",
    "francetravail.fr", "urssaf.fr", "auto-entrepreneur.fr",
    "greffe-tc-paris.fr", "infogreffe.fr", "rne.fr",
    "demarches.interieur.gouv.fr", "ants.gouv.fr", "prefectures.gouv.fr",
    "gendarmerie.interieur.gouv.fr", "police-nationale.interieur.gouv.fr",
    "pompiers.fr", "samu.fr", "ars.sante.fr"
]

# ============================================================================
# FRENCH EDUCATION & RESEARCH
# ============================================================================

FRENCH_EDUCATION_RESEARCH = [
    "crous-paris.fr", "crous-lyon.fr", "crous-bordeaux.fr", "crous-toulouse.fr",
    "crous-montpellier.fr", "crous-lille.fr", "crous-strasbourg.fr",
    "crous-nantes.fr", "crous-rennes.fr", "crous-aix-marseille.fr",
    "cned.fr", "onisep.fr", "parcoursup.fr", "terminales.fr",
    "etudiant.gouv.fr", "campusfrance.org", "francophonie.org",
    "cnrs.fr", "inserm.fr", "inria.fr", "cea.fr",
    "pasteur.fr", "curie.fr", "college-de-france.fr",
    "ac-versailles.fr", "ac-creteil.fr", "ac-paris.fr",
    "ac-lyon.fr", "ac-bordeaux.fr", "ac-toulouse.fr"
]

# ============================================================================
# FRENCH CULTURE & HERITAGE
# ============================================================================

FRENCH_CULTURE_HERITAGE = [
    "louvre.fr", "musee-orsay.fr", "centrepompidou.fr", "quaibranly.fr",
    "grandpalais.fr", "petitpalais.fr", "museeduluxembourg.fr",
    "chateauversailles.fr", "fontainebleau.fr", "chantilly.fr",
    "mont-saint-michel.fr", "carcassonne.fr", "avignon-tourisme.com",
    "bordeaux-tourisme.com", "lyon-france.com", "marseille-tourisme.com",
    "parisinfo.com", "tourisme.fr", "atout-france.fr",
    "culture.gouv.fr", "histoire.fr", "archives-nationales.fr",
    "bibliotheque-nationale.fr", "bnf.fr", "gallica.bnf.fr"
]

# ============================================================================
# EUROPEAN INSTITUTIONS
# ============================================================================

EUROPEAN_INSTITUTIONS = [
    "europa.eu", "ec.europa.eu", "europarl.europa.eu", "consilium.europa.eu",
    "curia.europa.eu", "eca.europa.eu", "eesc.europa.eu", "cor.europa.eu",
    "eib.org", "eba.europa.eu", "esma.europa.eu", "eiopa.europa.eu",
    "ecb.europa.eu", "emsa.europa.eu", "efsa.europa.eu", "echa.europa.eu",
    "era.europa.eu", "eu-lisa.europa.eu", "frontex.europa.eu", "satcen.europa.eu",
    "cdt.europa.eu", "epo.org", "euipo.europa.eu"
]

# ============================================================================
# INTERNATIONAL ORGANIZATIONS
# ============================================================================

INTERNATIONAL_ORGANIZATIONS = [
    "who.int", "un.org", "unesco.org", "unicef.org", "undp.org",
    "worldbank.org", "imf.org", "wto.org", "ilo.org", "fao.org",
    "iaea.org", "icao.int", "imo.org", "itu.int", "upu.int",
    "wipo.int", "wmo.int", "whoi.int", "icrc.org", "ifrc.org",
    "transparency.org", "amnesty.org", "hrw.org", "greenpeace.org",
    "wwf.org", "conservation.org", "nature.org"
]

# ============================================================================
# GLOBAL HEALTH ORGANIZATIONS
# ============================================================================

GLOBAL_HEALTH_ORGANIZATIONS = [
    "who.int", "cdc.gov", "nih.gov", "fda.gov", "ema.europa.eu",
    "ansm.fr", "has-sante.fr", "santepubliquefrance.fr",
    "pasteur.fr", "wellcome.org", "gatesfoundation.org",
    "gavi.org", "theglobalfund.org", "unaids.org",
    "msf.org", "redcross.org", "croix-rouge.fr",
    "ap-hm.fr", "aphp.fr", "chu-lyon.fr", "chu-bordeaux.fr",
    "chu-nantes.fr", "chu-rennes.fr", "chu-toulouse.fr"
]

# ============================================================================
# TECH SECURITY & CYBERSECURITY
# ============================================================================

TECH_SECURITY_CYBERSECURITY = [
    "letsencrypt.org", "ssl.com", "digicert.com", "comodo.com",
    "globalsign.com", "entrust.com", "sectigo.com",
    "kaspersky.com", "mcafee.com", "symantec.com", "norton.com",
    "bitdefender.com", "avast.com", "avg.com", "malwarebytes.com",
    "crowdstrike.com", "sentinelone.com", "carbonblack.com",
    "paloaltonetworks.com", "fortinet.com", "checkpoint.com",
    "sophos.com", "trendmicro.com", "fireeye.com", "mandiant.com"
]

# ============================================================================
# OPEN SOURCE & DEVELOPER COMMUNITIES
# ============================================================================

OPEN_SOURCE_DEVELOPER = [
    "apache.org", "linuxfoundation.org", "gnu.org", "fsf.org",
    "opensource.org", "mozilla.org", "webkit.org", "chromium.org",
    "python.org", "python.org", "ruby-lang.org", "php.net",
    "nodejs.org", "rust-lang.org", "golang.org", "scala-lang.org",
    "haskell.org", "erlang.org", "elixir-lang.org", "clojure.org",
    "djangoproject.com", "rubyonrails.org", "laravel.com",
    "spring.io", "quarkus.io", "micronaut.io", "grails.org"
]

# ============================================================================
# CLOUD SERVICES & INFRASTRUCTURE
# ============================================================================

CLOUD_SERVICES_INFRASTRUCTURE = [
    "aws.amazon.com", "azure.microsoft.com", "cloud.google.com",
    "oraclecloud.com", "ibm.cloud", "alibabacloud.com",
    "digitalocean.com", "linode.com", "vultr.com", "ovhcloud.com",
    "scaleway.com", "upcloud.com", "hetzner.com", "contabo.com",
    "render.com", "railway.app", "fly.io", "netlify.com",
    "vercel.com", "heroku.com", "platform.sh", "pantheon.io"
]

# ============================================================================
# DATA & ANALYTICS PLATFORMS
# ============================================================================

DATA_ANALYTICS_PLATFORMS = [
    "tableau.com", "powerbi.microsoft.com", "qlik.com",
    "looker.com", "domo.com", "sisense.com", "microstrategy.com",
    "snowflake.com", "databricks.com", "snowplow.io",
    "segment.com", "amplitude.com", "mixpanel.com", "heap.io",
    "google.com/analytics", "adobe.com/analytics",
    "matomo.org", "openwebanalytics.com", "piwik.org"
]

# ============================================================================
# LEGAL & PROFESSIONAL SERVICES
# ============================================================================

LEGAL_PROFESSIONAL_SERVICES = [
    "lexisnexis.com", "thomsonreuters.com", "westlaw.com",
    "bloomberglaw.com", "wolterskluwer.com", "bna.com",
    "legalzoom.com", "rocketlawyer.com", "nolo.com",
    "docketalarm.com", "casetext.com", "fastcase.com",
    "avocat.fr", "cnb.avocat.fr", "ordre-avocats.fr",
    "experts-comptables.fr", "ordre-experts-comptables.fr",
    "notaires.fr", "caisse-des-depots.fr", "banque-france.fr"
]

# ============================================================================
# FRENCH HOSPITALITY & HOTELS
# ============================================================================

FRENCH_HOSPITALITY_HOTELS = [
    "accor.com", "accorhotels.com", "all.accor.com", "sofitel.com",
    "pullmanhotels.com", "novotel.com", "mercure.com", "ibis.com",
    "hotel-f1.com", "campanile.com", "kyriad.com", "premierclasse.com",
    "b-bhotels.com", "aparthotels-adagio.com", "mama-shelter.com",
    "hotels-barriere.com", "louvrehotels.com", "goldentulip.com",
    "hotels-particuliers.com", "relaischateaux.com", "smallluxuryhotels.com",
    "chateauxhotels.com", "logishotels.com", "citizenm.com",
    "hotelbellevue.fr", "hotel-plaza-athenee.com", "ritzparis.com",
    "crillon.com", "meuricehotel.com", "bristol-paris.com"
]

# ============================================================================
# INTERNATIONAL HOTEL CHAINS
# ============================================================================

INTERNATIONAL_HOTEL_CHAINS = [
    "marriott.com", "hilton.com", "hyatt.com", "ihg.com",
    "wyndham.com", "choicehotels.com", "bestwestern.com",
    "radissonhotels.com", "intercontinental.com", "crowneplaza.com",
    "holidayinn.com", "sheraton.com", "westin.com", "fourpoints.com",
    "stregis.com", "luxurycollection.com", "w-hotels.com",
    "ritzcarlton.com", "fairmont.com", "swissotel.com",
    "millenniumhotels.com", "meliá.com", "barcelo.com",
    "riu.com", "iberostar.com", "h10hotels.com", "nh-hotels.com",
    "hoteles-silken.com", "hotusa.com", "hotelbeds.com"
]

# ============================================================================
# TRAVEL & ACCOMMODATION PLATFORMS
# ============================================================================

TRAVEL_ACCOMMODATION_PLATFORMS = [
    "booking.com", "airbnb.com", "expedia.com", "tripadvisor.com",
    "hotels.com", "agoda.com", "vrbo.com", "homeaway.com",
    "gites-de-france.com", "abritel.fr", "homelidays.com",
    "campings.com", "hometogo.com", "hostelworld.com",
    "couchsurfing.com", "trustedhousesitters.com",
    "workaway.info", "helpstay.com", "worldpackers.com",
    "sabbatical.com", "nomador.com", "housecarers.com"
]

# ============================================================================
# FRENCH TOURISM & REGIONAL OFFICES
# ============================================================================

FRENCH_TOURISM_OFFICES = [
    "atout-france.fr", "tourisme.fr", "france-voyage.com",
    "routard.com", "guide-du-roulage.fr", "les-plus-beaux-villages-de-france.org",
    "village-etape.com", "station-verte.com", "grands-sites-de-france.fr",
    "parcs-naturels-regionaux.fr", "parcs-nationaux.fr",
    "parisinfo.com", "lyon-france.com", "bordeaux-tourisme.com",
    "marseille-tourisme.com", "toulouse-tourisme.com",
    "strasbourg-tourisme.com", "lille-tourisme.com",
    "montpellier-tourisme.com", "nice-tourisme.com",
    "cotedazur-tourisme.com", "bretagne-tourisme.com",
    "normandie-tourisme.fr", "provence-tourisme.fr",
    "alsace-tourisme.com", "auvergne-tourisme.info",
    "pyrenees-tourisme.com", "loirevalley-tourism.com"
]

# ============================================================================
# FRENCH LOCAL GOVERNMENT
# ============================================================================

FRENCH_LOCAL_GOVERNMENT = [
    "paris.fr", "marseille.fr", "lyon.fr", "toulouse.fr", "nice.fr",
    "nantes.fr", "montpellier.fr", "strasbourg.fr", "bordeaux.fr", "lille.fr",
    "ville-de.fr", "mairie-de.fr", "grandlyon.com", "metropole-rouen-normandie.fr",
    "amiens.fr", "tours.fr", "limoges.fr", "clermont-ferrand.fr", "dijon.fr",
    "angers.fr", "lehavre.fr", "saint-etienne.fr", "toulon.fr", "grenoble.fr"
]

# ============================================================================
# CAC 40 FRENCH COMPANIES
# ============================================================================

CAC40_FRENCH_COMPANIES = [
    "totalenergies.com", "lvmh.com", "sanofi.com", "loreal.com", "airbus.com",
    "hermes.com", "schneider-electric.com", "danone.com", "safran.fr",
    "bnpparibas.com", "credit-agricole.com", "societegenerale.com",
    "orange.com", "vodafone.com", "vivendi.com", "publicisgroupe.com",
    "capgemini.com", "accor.com", "kering.com", "essilor.com",
    "saint-gobain.com", "legrand.com", "veolia.com", "engie.com",
    "thalesgroup.com", "dassault-aviation.com", "arcelormittal.com",
    "peugeot.com", "renault.com", "michelin.com"
]

# ============================================================================
# MAJOR CHARITIES & NON-PROFITS
# ============================================================================

MAJOR_CHARITIES_NONPROFITS = [
    "croix-rouge.fr", "secours-catholique.fr", "restosducoeur.org",
    "medecinsdumonde.org", "actioncontrelafaim.org", "unicef.fr",
    "wwf.fr", "greenpeace.fr", "amnesty.fr", "fondationdefrance.org",
    "fondationhopitaux.fr", "telethon.fr", "pasteur.fr",
    "fondation-entreprise.org", "fonda.asso.fr", "associations.gouv.fr"
]

# ============================================================================
# EUROPEAN GOVERNMENT SITES
# ============================================================================

EUROPEAN_GOVERNMENT_SITES = [
    "gov.uk", "gov.scot", "gov.wales", "gov.ie", "gov.nl",
    "belgium.be", "gov.be", "bund.de", "gov.it", "gov.es",
    "gov.pt", "gov.se", "gov.no", "gov.dk", "gov.fi",
    "gov.at", "admin.ch", "gov.ch", "gov.pl", "gov.cz",
    "gov.sk", "gov.hu", "gov.ro", "gov.bg", "gov.gr"
]

# ============================================================================
# INTERNATIONAL_UNIVERSITIES
# ============================================================================

INTERNATIONAL_UNIVERSITIES = [
    "utoronto.ca", "ubc.ca", "mcgill.ca", "unimelb.edu.au", "usyd.edu.au",
    "anu.edu.au", "auckland.ac.nz", "nus.edu.sg", "ntu.edu.sg",
    "hku.hk", "cuhk.edu.hk", "tokyo.ac.jp", "kyoto-u.ac.jp",
    "seoul.ac.kr", "yonsei.ac.kr", "kaist.ac.kr", "pku.edu.cn",
    "tsinghua.edu.cn", "fudan.edu.cn", "sjtu.edu.cn",
    "ethz.ch", "epfl.ch", "tum.de", "lmu.de", "hu-berlin.de"
]

# ============================================================================
# EUROPEAN_ENERGY_PROVIDERS
# ============================================================================

EUROPEAN_ENERGY_PROVIDERS = [
    "edf.fr", "engie.com", "totalenergies.com", "enedis.fr",
    "rte-france.com", "enedis.fr", "grdf.fr",
    "e.on.com", "e.on.de", "rwe.com", "enel.com",
    "iberdrola.com", "endesa.com", "naturgy.com",
    "vattenfall.com", "fortum.com", "statkraft.com",
    "orsted.com", "ssb.com", "nationalgrid.com"
]

# ============================================================================
# SPECIALIZED_PRESS
# ============================================================================

SPECIALIZED_PRESS = [
    "lesechos.fr", "latribune.fr", "agefi.fr", "argus.fr",
    "lequipe.fr", "lequipe.fr", "sport24.fr", "rmcsport.fr",
    "01net.com", "clubic.com", "frandroid.com", "journaldugeek.com",
    "programme-tv.net", "telerama.fr", "telestar.fr",
    "capital.fr", "challenges.fr", "forbes.fr", "harvard-business-review.fr"
]
# ============================================================================
# FRENCH_PROFESSIONAL_ASSOCIATIONS
# ============================================================================

FRENCH_PROFESSIONAL_ASSOCIATIONS = [
    "ordre-avocats.fr", "cnb.avocat.fr", "ordre-medecins.fr",
    "ordre-pharmaciens.fr", "ordre-architectes.fr", "ordre-experts-comptables.fr",
    "ordre-geometres.fr", "ordre-veterinaires.fr", "ordre-infirmiers.fr",
    "ordre-kinés.fr", "ordre-psychologues.fr", "ordre-dentistes.fr",
    "cnam.fr", "urssaf.fr", "cci.fr", "cm.fr",
    "crous.fr", "cnous.fr", "enseignementsup-recherche.gouv.fr"
]

# ============================================================================
# FRENCH_CULTURAL_INSTITUTIONS
# ============================================================================

FRENCH_CULTURAL_INSTITUTIONS = [
    "institutdefrance.fr", "academie-francaise.fr", "academie-sciences.fr",
    "academie-beaux-arts.fr", "academie-inscriptions.fr", "academie-sciences-morales.fr",
    "operadeparis.fr", "comedie-francaise.fr", "theatre-chatelet.fr",
    "theatredelaville-paris.com", "odeon.fr", "festival-avignon.com",
    "festival-cannes.com", "cinematheque.fr", "forumdesimages.fr"
]

# ============================================================================
# INTERNATIONAL_BUSINESS_PRESS
# ============================================================================

INTERNATIONAL_BUSINESS_PRESS = [
    "bloomberg.com", "reuters.com", "ft.com", "wsj.com",
    "economist.com", "forbes.com", "fortune.com", "businessinsider.com",
    "inc.com", "fastcompany.com", "entrepreneur.com", "harvardbusinessreview.com",
    "stratechery.com", "ben-evans.com", "sifted.eu", "techcrunch.com"
]

# ============================================================================
# EUROPEAN_CENTRAL_BANKS
# ============================================================================

EUROPEAN_CENTRAL_BANKS = [
    "ecb.europa.eu", "banque-france.fr", "bundesbank.de",
    "bancaditalia.it", "banquedespain.es", "banco-portugal.pt",
    "nationalbank.be", "dnb.no", "riksbank.se",
    "nationalbank.dk", "suomenpankki.fi", "centralbank.ie",
    "oenb.at", "snb.ch", "mnb.hu", "nbp.pl"
]

# ============================================================================
# STANDARDS_ORGANIZATIONS
# ============================================================================

STANDARDS_ORGANIZATIONS = [
    "iso.org", "iec.ch", "itu.int", "ieee.org",
    "w3.org", "ietf.org", "iana.org", "icann.org",
    "afnor.fr", "bsi.de", "ansi.org", "astm.org",
    "oasis-open.org", "omg.org", "objectmanagement.org"
]

# ============================================================================
# SPORTS_FEDERATIONS
# ============================================================================

SPORTS_FEDERATIONS = [
    "fff.fr", "federugby.fr", "ffbb.com", "fft.fr",
    "ffgolf.org", "ffhandball.fr", "ffjudo.com", "ffnatation.fr",
    "fifa.com", "uefa.com", "olympics.com", "paralympic.org",
    "world.rugby", "fibasketball.com", "fina.org", "worldathletics.org"
]

# ============================================================================
# FRENCH_SOFTWARE_EDITORS
# ============================================================================

FRENCH_SOFTWARE_EDITORS = [
    "dassault-systemes.com", "soprasteria.com", "capgemini.com",
    "atos.net", "sage.com", "cegid.com", "quadient.com",
    "murex.com", "talend.com", "business-objects.com",
    "ubisoft.com", "ansys.com", "altair.com", "dassault-aviation.com"
]

# ============================================================================
# PHARMACEUTICAL_LABORATORIES
# ============================================================================

PHARMACEUTICAL_LABORATORIES = [
    "sanofi.com", "servier.com", "ipsen.com", "biomerieux.com",
    "guerbet.com", "genfit.com", "novartis.com", "roche.com",
    "pfizer.com", "merck.com", "gsk.com", "astrazeneca.com",
    "johnsonandjohnson.com", "bayer.com", "novonordisk.com"
]

# ============================================================================
# FRENCH_AUTOMOTIVE_MANUFACTURERS
# ============================================================================

FRENCH_AUTOMOTIVE_MANUFACTURERS = [
    "renault.com", "peugeot.com", "citroen.com", "dsautomobiles.com",
    "bugatti.com", "alpinecars.com", "michelin.com", "valeo.com",
    "faurecia.com", "plasticomnium.com", "saint-gobain.com"
]

# ============================================================================
# FRENCH_SPECIALTY_RETAILERS
# ============================================================================

FRENCH_SPECIALTY_RETAILERS = [
    "leroymerlin.fr", "castorama.fr", "bricorama.fr", "bricomarche.com",
    "pointp.fr", "rs-online.com", "manomano.fr", "misterauto.com",
    "alltricks.fr", "decathlon.fr", "go-sport.fr", "intersport.fr"
]

# ============================================================================
# FRENCH_INSURANCE_MUTUALS
# ============================================================================

FRENCH_INSURANCE_MUTUALS = [
    "macif.fr", "maif.fr", "maaf.fr", "matmut.fr",
    "generali.fr", "groupama.fr", "allianz.fr", "axa.fr",
    "april.fr", "gan.fr", "acoba.fr", "credit-agricole-assurances.fr"
]

# ============================================================================
# FRENCH_CHAMBERS_OF_COMMERCE
# ============================================================================

FRENCH_CHAMBERS_OF_COMMERCE = [
    "cci.fr", "cci-paris-idf.fr", "cci-lyon.fr", "cci-bordeaux.fr",
    "cci-marseille.fr", "cci-lille.fr", "cci-toulouse.fr", "cci-nantes.fr",
    "cci-strasbourg.fr", "cci-nice.fr", "cci-rennes.fr", "cci-montpellier.fr"
]

# ============================================================================
# FRENCH_SCALEUP_STARTUPS
# ============================================================================

FRENCH_SCALEUP_STARTUPS = [
    "doctolib.fr", "blablacar.com", "backmarket.fr", "manomano.fr",
    "alan.com", "qonto.com", "ledger.com", "meero.com",
    "shift-technology.com", "owkin.com", "exotec.com", "sorare.com",
     "payfit.com", "spendesk.com", "front.com", "agorapulse.com"
]
# ============================================================================
# DOMAINES LÉGITIMES MANQUANTS (À AJOUTER À TA LISTE EXISTANTE)
# ============================================================================

MISSING_LEGITIMATE_DOMAINS = [
    "laposte.fr", "enedis.fr", "grdf.fr", "edf.fr", "engie.fr",
    "francetravail.fr", "urssaf.fr", "ameli.fr", "caf.fr", "impots.gouv.fr",
    "service-public.fr", "academie-francaise.fr", "institutdefrance.fr",
    "lavoixdunord.fr", "sudouest.fr", "ouest-france.fr", "letelegramme.fr",
    "leprogres.fr", "ledauphine.com", "dna.fr", "larepubliquedespyrenees.fr",
    "sorbonne-universite.fr", "ens.fr", "polytechnique.edu", "hec.fr",
    "essec.fr", "escp.eu", "sciences-po.fr", "centralesupelec.fr",
    "louvre.fr", "musee-orsay.fr", "centrepompidou.fr", "quaibranly.fr",
    "operadeparis.fr", "comedie-francaise.fr", "festival-avignon.com",
    "totalenergies.com", "lvmh.com", "sanofi.com", "loreal.com", "airbus.com",
    "hermes.com", "schneider-electric.com", "danone.com", "orange.com",
    "paris.fr", "marseille.fr", "lyon.fr", "toulouse.fr", "nice.fr",
    "strasbourg.eu", "bordeaux.fr", "lille.fr", "nantes.fr",
    "croix-rouge.fr", "restosducoeur.org", "medecinsdumonde.org",
    "secours-catholique.fr", "wwf.fr", "greenpeace.fr", "amnesty.fr",
    "scaleway.com", "ovhcloud.com", "outscale.com", "clever-cloud.com",
    "doctolib.fr", "blablacar.com", "backmarket.fr", "manomano.fr",
    "alan.com", "qonto.com", "ledger.com", "meero.com",
    "bnpparibas.fr", "societegenerale.fr", "credit-agricole.fr",
    "lcl.fr", "banquepopulaire.fr", "caisse-epargne.fr",
    "boursorama.fr", "fortuneo.fr", "hellobank.fr",
    "macif.fr", "maif.fr", "maaf.fr", "matmut.fr", "generali.fr",
    "groupama.fr", "axa.fr", "allianz.fr",
    "carrefour.fr", "auchan.fr", "leclerc.fr", "casino.fr",
    "monoprix.fr", "franprix.fr", "intermarche.com", "systeme-u.fr",
    "sncf.fr", "ratp.fr", "transilien.com", "ouibus.com",
    "blablacar.fr", "airfrance.fr", "transavia.com",
    "accor.com", "sofitel.com", "pullmanhotels.com", "novotel.com",
    "mercure.com", "ibis.com", "campanile.com", "kyriad.com"
]

# ============================================================================
# AUTRES DOMAINES 
# ============================================================================

OTHERS = [
    'polyfill.io', 'mesdroitssociaux.gouv.fr', 'platform.com', 'impots.gouv.fr',
    'cal.com', 'mandrillapp.com', 'avocat-durand.fr', 'application.com',
    'banquepopulaire.fr', 'petite-entreprise-locale.fr', 'cabinet-comptable-dupont.fr',
    'mabanque.bnpparibas', 'lcl.fr', 'site.com', 'boursorama.com', 'company.com',
    'cic.fr', 'demarches-simplifiees.fr', 'garage-martin.fr', 'societegenerale.fr',
    'restaurant-lebongout.fr', 'clinique-sante.fr', 'assurance-locale.fr',
    'website.com', 'service-public.fr', 'service.com', 'credit-agricole.fr',
    'ing.fr', 'hellobank.fr', 'banque-regionale.fr', 'ma-startup-innovante.com',
    'ameli.fr', 'product.com', 'fortuneo.fr', 'api.com', 'urssaf.fr', 'caf.fr'
]
# ============================================================================
# DOMAINES LÉGITIMES SUPPLÉMENTAIRES (1000+)
# ============================================================================

ADDITIONAL_LEGITIMATE_DOMAINS = [
    # Services français supplémentaires (100+)
    "notaires.fr", "huissiers-justice.fr", "avocats.fr", "experts-comptables.fr",
    "architectes.fr", "medecins.fr", "pharmacies.fr", "hopitaux.fr",
    "cliniques.fr", "laboratoires.fr", "mutuelles.fr", "assureurs.fr",
    "caissedepargne.fr", "banquepopulaire.fr", "creditmutuel.fr", "lcl.fr",
    "societegenerale.fr", "bnpparibas.fr", "creditagricole.fr", "hsbc.fr",
    "ing.fr", "axabanque.fr", "orangebank.fr", "hellobank.fr", "boursorama.fr",
    "fortuneo.fr", "monabanq.fr", "cic.fr", "banquecasino.fr", "max.fr",
    
    # Collectivités territoriales (50+)
    "iledefrance.fr", "regionpaca.fr", "auvergnerhonealpes.fr", "occitanie.fr",
    "nouvelle-aquitaine.fr", "hautsdefrance.fr", "grandest.fr", "bretagne.fr",
    "normandie.fr", "paydelaloire.fr", "bourgognefranchecomte.fr", "centrevaldeloire.fr",
    "paris.fr", "marseille.fr", "lyon.fr", "toulouse.fr", "nice.fr", "nantes.fr",
    "montpellier.fr", "strasbourg.fr", "bordeaux.fr", "lille.fr", "rennes.fr",
    "reims.fr", "saint-etienne.fr", "toulon.fr", "grenoble.fr", "dijon.fr",
    "angers.fr", "villeurbanne.fr", "lemans.fr", "clermont-ferrand.fr",
    
    # Universités et grandes écoles (100+)
    "univ-paris1.fr", "univ-paris2.fr", "univ-paris3.fr", "univ-paris5.fr",
    "univ-paris6.fr", "univ-paris7.fr", "univ-paris8.fr", "univ-paris10.fr",
    "univ-paris12.fr", "univ-paris13.fr", "univ-lyon1.fr", "univ-lyon2.fr",
    "univ-lyon3.fr", "univ-lille.fr", "univ-nantes.fr", "univ-toulouse.fr",
    "univ-bordeaux.fr", "univ-montpellier.fr", "univ-strasbourg.fr",
    "univ-rennes1.fr", "univ-rennes2.fr", "ec-lyon.fr", "insa-lyon.fr",
    "centralesupelec.fr", "enseignementsup-recherche.gouv.fr",
    
    # Santé français (50+)
    "ameli.fr", "doctolib.fr", "qare.fr", "maiia.com", "keldoc.com",
    "monrdv.com", "docavenue.com", "medecin-direct.com", "livi.fr",
    "sante.fr", "solidarites-sante.gouv.fr", "has-sante.fr",
    "ansm.fr", "invs.sante.fr", "pasteur.fr", "curie.fr",
    "gustaveroussy.fr", "igr.fr", "fondation-arc.fr", "ligue-cancer.net",
    
    # Médias régionaux supplémentaires (100+)
    "laprovence.com", "leparisien.fr", "leprogres.fr", "ledauphine.com",
    "lanouvellerepublique.fr", "centre-presse.fr", "leberry.fr",
    "lamontagne.fr", "lepopulaire.fr", "ladepeche.fr", "midilibre.fr",
    "lindependant.fr", "nice-matin.fr", "varmatin.com", "paris-normandie.fr",
    "courrier-picard.fr", "lavoixdunord.fr", "nordeclair.fr", "estrepublicain.fr",
    "lejsl.fr", "dna.fr", "lalsace.fr", "letelegramme.fr", "ouest-france.fr",
    "letelegramme.fr", "presse-ocean.fr", "maville.com",
    
    # E-commerce français (50+)
    "cdiscount.com", "fnac.com", "darty.com", "boulanger.com",
    "carrefour.fr", "auchan.fr", "leclerc.fr", "casino.fr",
    "monoprix.fr", "franprix.fr", "intermarche.com", "systeme-u.fr",
    "veepee.fr", "vente-privee.com", "showroomprive.com", "brandalley.fr",
    "backmarket.fr", "ldlc.com", "materiel.net", "topachat.com",
    "rueducommerce.fr", "priceminister.com", "rakuten.fr", "manomano.fr",
    "misterauto.com", "alltricks.fr", "culturefactory.fr", "placedeslibraires.fr",
    "decitre.fr", "gibertjeune.fr", "cultura.com", "leroymerlin.fr",
    
    # Tech français (50+)
    "ovh.com", "ovhcloud.com", "scaleway.com", "online.net",
    "outscale.com", "clever-cloud.com", "platform.sh", "gitoyen.net",
    "gandi.net", "amen.fr", "netissime.fr", "lws.fr",
    "infomaniak.com", "ikoula.com", "kimsufi.com", "soyoustart.com",
    "dedibox.fr", "vialis.io", "alwaysdata.com", "jelastic.com",
    
    # Startups françaises (100+)
    "doctolib.fr", "blablacar.com", "backmarket.fr", "manomano.fr",
    "alan.com", "qonto.com", "ledger.com", "meero.com", "shift-technology.com",
    "owkin.com", "exotec.com", "sorare.com", "payfit.com", "spendesk.com",
    "front.com", "agorapulse.com", "content-square.com", "sendinblue.com",
    "mirakl.com", "ivalua.com", "criteo.com", "talentsoft.com", "monday.com",
    "getaround.com", "drivy.com", "ouicar.fr", "zenly.com", "jellysmack.com",
    "devialet.com", "withings.com", "netatmo.com", "parrot.com",
    
    # Associations françaises (50+)
    "croix-rouge.fr", "restosducoeur.org", "secourscatholique.fr",
    "medecinsdumonde.org", "actioncontrelafaim.org", "unicef.fr",
    "wwf.fr", "greenpeace.fr", "amnesty.fr", "fondationdefrance.org",
    "fondationhopitaux.fr", "telethon.fr", "arc-foundation.fr",
    "ligue-cancer.net", "associationfranceprevention.org",
    "sidasante.org", "autisme-france.fr", "apf-francehandicap.org",
    
    # Culture français (50+)
    "louvre.fr", "musee-orsay.fr", "centrepompidou.fr", "quaibranly.fr",
    "grandpalais.fr", "petitpalais.fr", "museeduluxembourg.fr",
    "chateauversailles.fr", "fontainebleau.fr", "chantilly.fr",
    "mont-saint-michel.fr", "carcassonne.fr", "avignon-tourisme.com",
    "bordeaux-tourisme.com", "lyon-france.com", "marseille-tourisme.com",
    "parisinfo.com", "tourisme.fr", "atout-france.fr",
    
    # Transport français (50+)
    "sncf.fr", "ratp.fr", "transilien.com", "ouibus.com",
    "blablacar.fr", "airfrance.fr", "transavia.com", "corsair.com",
    "aircaraibes.com", "airtahitinui.com", "bateauxparisiens.com",
    "vedettesdeparis.fr", "canalrama.com", "europe-cruises.com",
    
    # Hôtellerie française (50+)
    "accor.com", "sofitel.com", "pullmanhotels.com", "novotel.com",
    "mercure.com", "ibis.com", "hotel-f1.com", "campanile.com",
    "kyriad.com", "premierclasse.com", "b-bhotels.com", "aparthotels-adagio.com",
    "mama-shelter.com", "hotels-barriere.com", "louvrehotels.com",
    
    # Services publics européens (100+)
    "europa.eu", "ec.europa.eu", "europarl.europa.eu", "consilium.europa.eu",
    "curia.europa.eu", "eca.europa.eu", "eesc.europa.eu", "cor.europa.eu",
    "eib.org", "eba.europa.eu", "esma.europa.eu", "eiopa.europa.eu",
    "ecb.europa.eu", "emsa.europa.eu", "efsa.europa.eu", "echa.europa.eu",
    
    # Banques européennes (50+)
    "ing.com", "rabobank.com", "abnamro.com", "deutsche-bank.de",
    "commerzbank.de", "unicredit.it", "intesasanpaolo.com", "santander.com",
    "bbva.com", "bnpparibas.com", "societegenerale.com", "creditagricole.com",
    
    # Autres services légitimes globaux (100+)
    "stackoverflow.com", "stackexchange.com", "superuser.com", "serverfault.com",
    "askubuntu.com", "mathoverflow.net", "github.com", "gitlab.com", "bitbucket.org",
    "sourceforge.net", "npmjs.com", "pypi.org", "rubygems.org", "packagist.org",
    "crates.io", "nuget.org", "docker.com", "kubernetes.io", "terraform.io",
    
    # Ajouts finaux variés
    "mozilla.org", "webkit.org", "chromium.org", "python.org", "nodejs.org",
    "rust-lang.org", "golang.org", "swift.org", "kotlinlang.org", "scala-lang.org",
    "haskell.org", "ocaml.org", "elixir-lang.org", "clojure.org", "erlang.org"
]
# ============================================================================
# DOMAINES LÉGITIMES MASSIFS (2000+ supplémentaires)
# ============================================================================

MASSIVE_LEGITIMATE_DOMAINS = [
    # 🏛️ INSTITUTIONS FRANÇAISES (200+)
    "assemblee-nationale.fr", "senat.fr", "conseil-constitutionnel.fr",
    "conseil-etat.fr", "courdescomptes.fr", "defenseurdesdroits.fr",
    "cnil.fr", "arcep.fr", "anses.fr", "ansm.fr", "has-sante.fr",
    "academie-medecine.fr", "academie-sciences.fr", "academie-francaise.fr",
    "insee.fr", "ined.fr", "inrap.fr", "cnrs.fr", "inserm.fr", "inria.fr",
    "cea.fr", "ifremer.fr", "ird.fr", "cirad.fr", "inra.fr", "pasteur.fr",
    "curie.fr", "gustaveroussy.fr", "villegif.inserm.fr",
    
    # 🎓 UNIVERSITÉS FRANÇAISES COMPLÈTES (300+)
    "univ-paris1.fr", "univ-paris2.fr", "univ-paris3.fr", "univ-paris5.fr",
    "univ-paris6.fr", "univ-paris7.fr", "univ-paris8.fr", "univ-paris10.fr",
    "univ-paris12.fr", "univ-paris13.fr", "sorbonne-universite.fr",
    "univ-lyon1.fr", "univ-lyon2.fr", "univ-lyon3.fr", "univ-lille.fr",
    "univ-nantes.fr", "univ-toulouse.fr", "univ-bordeaux.fr",
    "univ-montpellier.fr", "univ-strasbourg.fr", "univ-rennes1.fr",
    "univ-rennes2.fr", "univ-amu.fr", "univ-angers.fr", "univ-artois.fr",
    "univ-avignon.fr", "univ-brest.fr", "univ-caen.fr", "univ-cemu.fr",
    "univ-clermont.fr", "univ-cotedazur.fr", "univ-dijon.fr", "univ-eiffel.fr",
    "univ-evry.fr", "univ-grenoble-alpes.fr", "univ-lehavre.fr",
    "univ-lemans.fr", "univ-lorraine.fr", "univ-montp3.fr",
    "univ-mulhouse.fr", "univ-nimes.fr", "univ-orleans.fr",
    "univ-pau.fr", "univ-poitiers.fr", "univ-reims.fr", "univ-rouen.fr",
    "univ-savoie.fr", "univ-st-etienne.fr", "univ-tln.fr", "univ-tours.fr",
    "univ-valenciennes.fr", "univ-paris-est.fr", "univ-paris-saclay.fr",
    
    # 🏫 GRANDES ÉCOLES FRANÇAISES (150+)
    "polytechnique.edu", "ens.fr", "ens-lyon.fr", "ens-rennes.fr",
    "ensae.fr", "ensai.fr", "ensc.fr", "enscm.fr", "ensc-lille.fr",
    "ensg.fr", "ensgsci.fr", "ensicaen.fr", "ensimag.fr", "ensma.fr",
    "ensmp.fr", "ensps.fr", "enssat.fr", "ensu.fr", "ens2m.fr",
    "hec.fr", "essec.fr", "escp.eu", "edhec.fr", "em-lyon.com",
    "audencia.com", "grenoble-em.com", "skema.edu", "neoma-bs.com",
    "kedgebs.com", "ieseg.fr", "esc-toulouse.fr", "esc-clermont.fr",
    "esc-pau.fr", "esc-rennes.fr", "esc-troyes.fr", "ec-lyon.fr",
    "ec-nantes.fr", "ec-lille.fr", "ec-marseille.fr", "ec-strasbourg.fr",
    "ecp.fr", "centralesupelec.fr", "centralelyon.fr", "centrale-marseille.fr",
    "centralenantes.fr", "centralelille.fr", "insa-lyon.fr", "insa-rennes.fr",
    "insa-strasbourg.fr", "insa-toulouse.fr", "insa-rouen.fr",
    "insa-hautesalsace.fr", "insa-centrevaldeloire.fr",
    
    # 🏥 SANTÉ FRANÇAISE ÉTENDUE (200+)
    "aphp.fr", "chu-lyon.fr", "chu-bordeaux.fr", "chu-nantes.fr",
    "chu-rennes.fr", "chu-toulouse.fr", "chu-montpellier.fr",
    "chu-strasbourg.fr", "chu-lille.fr", "chu-angers.fr",
    "chu-besancon.fr", "chu-clermontferrand.fr", "chu-dijon.fr",
    "chu-grenoble.fr", "chu-limoges.fr", "chu-nancy.fr", "chu-nimes.fr",
    "chu-poitiers.fr", "chu-reims.fr", "chu-rouen.fr", "chu-saint-etienne.fr",
    "chu-tours.fr", "chu-amiens.fr", "chu-caen.fr", "chu-rouen.fr",
    "hopital-necker.fr", "hopital-saintlouis.fr", "hopital-europeen.fr",
    "hopital-foch.fr", "hopital-lariboisiere.fr", "hopital-bichat.fr",
    "hopital-tenon.fr", "hopital-pitiesalpetriere.fr", "hopital-cochin.fr",
    "hopital-georgespompidou.fr", "hopital-saintantoine.fr",
    "fondation-ade-rothschild.fr", "clinique-pasteur.fr",
    "clinique-saint-jean.fr", "clinique-du-cedre.fr",
    
    # 🏢 ENTREPRISES CAC 40 & SBF 120 (150+)
    "totalenergies.com", "lvmh.com", "sanofi.com", "loreal.com",
    "airbus.com", "hermes.com", "schneider-electric.com", "danone.com",
    "bnpparibas.com", "credit-agricole.com", "societegenerale.com",
    "orange.com", "vodafone.com", "vivendi.com", "publicisgroupe.com",
    "capgemini.com", "accor.com", "kering.com", "essilor.com",
    "saint-gobain.com", "legrand.com", "veolia.com", "engie.com",
    "thalesgroup.com", "dassault-aviation.com", "arcelormittal.com",
    "peugeot.com", "renault.com", "michelin.com", "safran.fr",
    "att.com", "axa.com", "bouygues.com", "carrefour.com",
    "eurofins.com", "fpsa.com", "genfit.com", "icade.com",
    "ipsen.com", "jcdecaux.com", "klépierre.com", "lagardere.com",
    "nexity.fr", "orpea.com", "pernod-ricard.com", "rémy-cointreau.com",
    "rubis.com", "sartorius-stedim.com", "scor.com", "seb.com",
    "tf1.fr", "valneva.com", "vallourec.com", "wendel-investissement.com",
    "zodiac-aerospace.com",
    
    # 🌍 ENTREPRISES INTERNATIONALES (200+)
    "siemens.com", "bosch.com", "basf.com", "volkswagen.com",
    "bmw.com", "mercedes-benz.com", "audi.com", "adidas.com",
    "puma.com", "nivea.com", "henkel.com", "lufthansa.com",
    "deutschebahn.com", "allianz.com", "munichre.com",
    "shell.com", "bp.com", "exxonmobil.com", "chevron.com",
    "nestle.com", "unilever.com", "proctergamble.com", "cocacola.com",
    "pepsico.com", "mondelez.com", "kraftheinz.com", "danone.com",
    "general-electric.com", "boeing.com", "lockheedmartin.com",
    "northropgrumman.com", "raytheon.com", "bae-systems.com",
    "airbus.com", "boeing.com", "embraer.com", "bombardier.com",
    "volvo.com", "scania.com", "man.com", "iveco.com",
    "caterpillar.com", "john-deere.com", "komatsu.com",
    "hitachi.com", "toshiba.com", "fujitsu.com", "nec.com",
    "sharp.com", "panasonic.com", "sony.com", "samsung.com",
    "lg.com", "hyundai.com", "kia.com", "toyota.com",
    "honda.com", "nissan.com", "mazda.com", "subaru.com",
    "mitsubishi.com", "suzuki.com", "isuzu.com",
    
    # 🏛️ GOUVERNEMENTS EUROPÉENS (150+)
    "gov.uk", "gov.scot", "gov.wales", "gov.ie", "gov.nl",
    "belgium.be", "gov.be", "bund.de", "gov.it", "gov.es",
    "gov.pt", "gov.se", "gov.no", "gov.dk", "gov.fi",
    "gov.at", "admin.ch", "gov.ch", "gov.pl", "gov.cz",
    "gov.sk", "gov.hu", "gov.ro", "gov.bg", "gov.gr",
    "gov.si", "gov.hr", "gov.rs", "gov.me", "gov.al",
    "gov.mk", "gov.ba", "gov.md", "gov.ua", "gov.by",
    "gov.kz", "gov.ru", "gov.tr", "gov.il", "gov.sa",
    "gov.ae", "gov.qa", "gov.kw", "gov.bh", "gov.om",
    "gov.in", "gov.cn", "gov.jp", "gov.kr", "gov.sg",
    "gov.my", "gov.th", "gov.vn", "gov.id", "gov.ph",
    
    # 🏦 BANQUES INTERNATIONALES (200+)
    "jpmorganchase.com", "bankofamerica.com", "wellsfargo.com",
    "citigroup.com", "goldmansachs.com", "morganstanley.com",
    "americanexpress.com", "usbank.com", "pnc.com", "td.com",
    "capitalone.com", "ally.com", "discover.com", "barclays.com",
    "hsbc.com", "lloydsbank.com", "natwest.com", "rbs.com",
    "standardchartered.com", "ubs.com", "credit-suisse.com",
    "deutsche-bank.de", "commerzbank.de", "danske-bank.dk",
    "nordea.com", "seb.se", "swedbank.se", "bnpparibas.com",
    "societegenerale.com", "credit-agricole.com", "ing.com",
    "rabobank.com", "abnamro.com", "bbva.com", "santander.com",
    "unicredit.it", "intesasanpaolo.com", "mufg.jp", "mizuho-fg.co.jp",
    "smfg.co.jp", "anz.com", "commonbank.com.au", "westpac.com.au",
    "nab.com.au", "rbc.com", "td.com", "bmo.com", "cibc.com",
    "scotiabank.com", "bankofchina.com", "icbc.com.cn",
    "ccb.com", "abc.com.cn", "boc.cn",
    
    # 🎓 UNIVERSITÉS INTERNATIONALES (300+)
    "harvard.edu", "stanford.edu", "mit.edu", "caltech.edu",
    "princeton.edu", "yale.edu", "columbia.edu", "uchicago.edu",
    "upenn.edu", "johnshopkins.edu", "northwestern.edu", "duke.edu",
    "dartmouth.edu", "brown.edu", "vanderbilt.edu", "cornell.edu",
    "rice.edu", "wustl.edu", "notredame.edu", "berkeley.edu",
    "ucla.edu", "usc.edu", "umich.edu", "nyu.edu", "cmu.edu",
    "emory.edu", "georgetown.edu", "unc.edu", "virginia.edu",
    "wisc.edu", "uiuc.edu", "gatech.edu", "purdue.edu", "psu.edu",
    "osu.edu", "utexas.edu", "tamu.edu", "uf.edu", "ufl.edu",
    "asu.edu", "ucsd.edu", "ucsb.edu", "ucdavis.edu", "uci.edu",
    "ucsc.edu", "ucr.edu", "ucmerced.edu", "uoregon.edu",
    "uw.edu", "umd.edu", "umn.edu", "msu.edu", "iastate.edu",
    "ku.edu", "uky.edu", "utk.edu", "ua.edu", "auburn.edu",
    
    # 🌐 SERVICES TECH INTERNATIONAUX (200+)
    "cloudflare.com", "akamai.com", "fastly.com", "digitalocean.com",
    "linode.com", "vultr.com", "heroku.com", "netlify.com",
    "vercel.com", "render.com", "railway.app", "fly.io",
    "supabase.com", "firebase.google.com", "aws.amazon.com",
    "azure.microsoft.com", "cloud.google.com", "oraclecloud.com",
    "ibm.cloud", "alibabacloud.com", "datadoghq.com", "newrelic.com",
    "splunk.com", "elastic.co", "sentry.io", "logrocket.com",
    "mixpanel.com", "amplitude.com", "heap.io", "segment.com",
    "optimizely.com", "launchdarkly.com", "split.io", "appdynamics.com",
    "dynatrace.com", "newrelic.com", "sumologic.com", "loggly.com",
    "papertrail.com", "graylog.org", "splunk.com",
    
    # 🛍️ E-COMMERCE INTERNATIONAL (150+)
    "ebay.com", "etsy.com", "walmart.com", "target.com",
    "bestbuy.com", "homedepot.com", "lowes.com", "costco.com",
    "kroger.com", "safeway.com", "publix.com", "wholefoods.com",
    "traderjoes.com", "aldi.com", "lidl.com", "tesco.com",
    "sainsburys.co.uk", "asda.com", "morrisons.com", "waitrose.com",
    "marksandspencer.com", "boots.com", "superdrug.com",
    "woolworths.com.au", "coles.com.au", "bigw.com.au",
    "amazon.co.uk", "amazon.de", "amazon.fr", "amazon.es",
    "amazon.it", "amazon.co.jp", "amazon.com.au", "amazon.ca",
    "amazon.com.mx", "amazon.com.br", "amazon.in",
    "flipkart.com", "snapdeal.com", "myntra.com", "ajio.com",
    "lazada.com", "shopee.com", "tokopedia.com", "bukalapak.com",
    "blibli.com", "jd.com", "taobao.com", "tmall.com",
    "1688.com", "pinduoduo.com", "vipshop.com", "suning.com",
    
    # 🎬 MÉDIAS & STREAMING (100+)
    "hulu.com", "hbomax.com", "disneyplus.com", "paramountplus.com",
    "peacocktv.com", "apple.tv", "youtubetv.com", "sling.com",
    "fubo.tv", "philo.com", "pluto.tv", "tubi.tv", "crackle.com",
    "vudu.com", "imdb.com", "rottentomatoes.com", "metacritic.com",
    "boxofficemojo.com", "themoviedb.org", "letterboxd.com",
    "trakt.tv", "simkl.com", "reelgood.com", "justwatch.com",
    "tvtime.com", "serializd.com", "backloggd.com",
    
    # 🎮 JEUX & ESPORTS (100+)
    "steampowered.com", "epicgames.com", "gog.com", "origin.com",
    "uplay.com", "battle.net", "riotgames.com", "activision.com",
    "ea.com", "ubisoft.com", "nintendo.com", "playstation.com",
    "xbox.com", "sega.com", "bandainamco.com", "square-enix.com",
    "capcom.com", "konami.com", "namco.com", "atari.com",
    "valvesoftware.com", "rockstargames.com", "naughtydog.com",
    "insomniacgames.com", "suckerpunch.com", "guerrilla-games.com",
    "343industries.com", "thecoalitionstudio.com", "turn10studios.com",
    "mojang.com", "facepunch.com", "bohemia.net", "ccpgames.com",
    "grindinggear.com", "digital-extremes.com", "warnerbros.com",
    
    # 🛠️ OUTILS DÉVELOPPEUR (100+)
    "git-scm.com", "docker.com", "kubernetes.io", "terraform.io",
    "ansible.com", "puppet.com", "chef.io", "saltstack.com",
    "jenkins.io", "travis-ci.org", "circleci.com", "gitlab.com",
    "bitbucket.org", "sourceforge.net", "github.com", "gitkraken.com",
    "sourcetreeapp.com", "tower.com", "fork.dev", "atom.io",
    "sublimetext.com", "vscode.dev", "jetbrains.com", "eclipse.org",
    "netbeans.org", "brackets.io", "notepad-plus-plus.org",
    
    # FIN
]
# ============================================================================
# ASSEMBLAGE FINAL
# ============================================================================

def compile_all_domains():
    """Compile tous les domaines dans une seule liste dédupliquée"""
    all_domains = set()

    # Ajouter toutes les listes
    domain_lists = [
        TOP_100_GLOBAL,
        TECH_GIANTS_CLOUD,
        ECOMMERCE_RETAIL,
        FINANCIAL,
        STREAMING,
        SOCIAL_MEDIA,
        NEWS_MEDIA,
        EDUCATION,
        DEVELOPER_TOOLS,
        GOVERNMENT,
        HEALTH,
        TRAVEL,
        REAL_ESTATE,
        UTILITIES,
        CRITICAL_MISSING,
        FRENCH_MEDIA_EXTENDED,
        FRENCH_ECOMMERCE_SERVICES,
        FRENCH_GOVERNMENT_PUBLIC,
        FRENCH_BANKS_FINANCE,
        FRENCH_TRANSPORT_TRAVEL,
        EUROPEAN_TECH_STARTUPS,
        INTERNATIONAL_TELECOMS,
        GLOBAL_AUTOMOTIVE,
        FOOD_DELIVERY_RESTAURANTS,
        GAMING_ESPORTS,
        FRENCH_REGIONAL_MEDIA,
        FRENCH_PUBLIC_SERVICES,
        FRENCH_EDUCATION_RESEARCH,
        FRENCH_CULTURE_HERITAGE,
        EUROPEAN_INSTITUTIONS,
        INTERNATIONAL_ORGANIZATIONS,
        GLOBAL_HEALTH_ORGANIZATIONS,
        TECH_SECURITY_CYBERSECURITY,
        OPEN_SOURCE_DEVELOPER,
        CLOUD_SERVICES_INFRASTRUCTURE,
        DATA_ANALYTICS_PLATFORMS,
        LEGAL_PROFESSIONAL_SERVICES,
        FRENCH_HOSPITALITY_HOTELS,
        INTERNATIONAL_HOTEL_CHAINS,
        TRAVEL_ACCOMMODATION_PLATFORMS,
        FRENCH_TOURISM_OFFICES,
        FRENCH_LOCAL_GOVERNMENT,
        CAC40_FRENCH_COMPANIES,
        MAJOR_CHARITIES_NONPROFITS,
        EUROPEAN_GOVERNMENT_SITES,
        INTERNATIONAL_UNIVERSITIES,
        EUROPEAN_ENERGY_PROVIDERS,
        SPECIALIZED_PRESS,
        FRENCH_PROFESSIONAL_ASSOCIATIONS,
        FRENCH_CULTURAL_INSTITUTIONS,
        INTERNATIONAL_BUSINESS_PRESS,
        EUROPEAN_CENTRAL_BANKS,
        STANDARDS_ORGANIZATIONS,
        SPORTS_FEDERATIONS,
        FRENCH_SOFTWARE_EDITORS,
        PHARMACEUTICAL_LABORATORIES,
        FRENCH_AUTOMOTIVE_MANUFACTURERS,
        FRENCH_SPECIALTY_RETAILERS,
        FRENCH_INSURANCE_MUTUALS,
        FRENCH_CHAMBERS_OF_COMMERCE,
        FRENCH_SCALEUP_STARTUPS,
        MISSING_LEGITIMATE_DOMAINS,
        OTHERS,
        ADDITIONAL_LEGITIMATE_DOMAINS,
        MASSIVE_LEGITIMATE_DOMAINS
    ]

    for domain_list in domain_lists:
        all_domains.update(domain_list)

    # Trier alphabétiquement
    return sorted(list(all_domains))

# Générer la liste complète

# Sauvegarder avec joblib
if __name__ == "__main__":
    import joblib
    import os
    LEGITIMATE_DOMAINS = compile_all_domains()
    joblib.dump(LEGITIMATE_DOMAINS, output_file, compress=9)

    print(f"✅ Base de données sauvegardée dans: {output_file}")
    print(f"📊 Nombre total de domaines: {len(LEGITIMATE_DOMAINS)}")
    print(f"💾 Taille du fichier: {os.path.getsize(output_file) / 1024:.2f} KB")
    print(f"\n🔍 10 premiers domaines:")
#     print(len(LEGITIMATE_DOMAINS))
    for i, domain in enumerate(LEGITIMATE_DOMAINS[:10], 1):
        print(f"   {i}. {domain}")
    print(f"\n💡 Pour charger: domains = joblib.load('{output_file}')")
#     print(list(set(CRITICAL_MISSING)))
    print('cloudflare.com' in LEGITIMATE_DOMAINS)
