#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Fri Oct 31 20:57:54 2025

@author: hounsousamuel
"""

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
BATTERIE DE TESTS COMPLEXES - URLs Réalistes
Pour tester la robustesse de ton modèle anti-phishing
"""
import os, sys
sys.path.insert(1, os.path.dirname(os.path.abspath(os.path.join(__file__, ".."))))
# from core.features_extractor import _get_domain, features_extractor_from_url
# from core.generator import LEGITIMATE_DOMAINS
# ============================================================================
# 🟢 CATÉGORIE 1: URLs LÉGITIMES COMPLEXES (Doivent être SAFE)
# ============================================================================

LEGITIMATE_COMPLEX = {
    "Authentification légitime": [
        "https://accounts.google.com/ServiceLogin?service=mail",
        "https://login.microsoftonline.com/common/oauth2/authorize",
        "https://appleid.apple.com/sign-in",
        "https://www.amazon.com/ap/signin?openid.return_to=https%3A%2F%2Fwww.amazon.com%2F",
        "https://login.live.com/login.srf?wa=wsignin1.0",
        "https://auth.netflix.com/login",
        "https://secure.paypal.com/signin?returnUri=https%3A%2F%2Fwww.paypal.com%2Fmyaccount",
        "https://github.com/login?return_to=%2Fuser%2Frepos",
        "https://signin.aws.amazon.com/signin",
        "https://id.atlassian.com/login",
    ],

    "Sous-domaines légitimes multiples": [
        "https://mail.google.com/mail/u/0/",
        "https://drive.google.com/drive/my-drive",
        "https://docs.google.com/document/d/abc123/edit",
        "https://calendar.google.com/calendar/render",
        "https://meet.google.com/abc-defg-hij",
        "https://teams.microsoft.com/l/meetup-join/",
        "https://outlook.office.com/mail/inbox",
        "https://portal.azure.com/#home",
        "https://console.cloud.google.com/home/dashboard",
        "https://s3.console.aws.amazon.com/s3/home",
    ],

    "URLs avec tokens/IDs légitimes": [
        "https://zoom.us/j/1234567890?pwd=abcdefghijklmnop",
        "https://calendly.com/johndoe/30min?month=2025-01",
        "https://typeform.com/to/AbCdEf12",
        "https://forms.gle/1a2B3c4D5e6F7g8H",
        "https://bit.ly/3xYz123",
        "https://t.co/AbCdEfGhIj",
        "https://amzn.to/3aBcDeF",
        "https://youtu.be/dQw4w9WgXcQ",
        "https://goo.gl/maps/aBcDeFgHiJkLmNo",
        "https://www.dropbox.com/sh/abc123def456/AaBbCc?dl=0",
    ],

    "APIs et webhooks légitimes": [
        "https://api.github.com/repos/owner/repo/issues",
        "https://api.stripe.com/v1/charges",
        "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXX",
        "https://discord.com/api/webhooks/123456789/abcdefghijklmnop",
        "https://graph.microsoft.com/v1.0/me",
        "https://api.openai.com/v1/chat/completions",
        "https://www.googleapis.com/oauth2/v1/userinfo",
        "https://api.twitter.com/2/tweets",
        "https://graph.facebook.com/v18.0/me",
        "https://api.linkedin.com/v2/me",
    ],

    "CDN et ressources statiques": [
        "https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css",
        "https://unpkg.com/react@18/umd/react.production.min.js",
        "https://cdnjs.cloudflare.com/ajax/libs/jquery/3.6.0/jquery.min.js",
        "https://fonts.googleapis.com/css2?family=Roboto:wght@400;700",
        "https://use.fontawesome.com/releases/v5.15.4/css/all.css",
        "https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/js/bootstrap.min.js",
        "https://ajax.googleapis.com/ajax/libs/angularjs/1.8.2/angular.min.js",
        "https://code.jquery.com/jquery-3.6.0.slim.min.js",
        "https://maxcdn.bootstrapcdn.com/font-awesome/4.7.0/css/font-awesome.min.css",
        "https://polyfill.io/v3/polyfill.min.js",
    ],

    "Services cloud légitimes": [
        "https://app.slack.com/client/T012345/C012345",
        "https://app.asana.com/0/1234567890/1234567890",
        "https://trello.com/b/AbCdEfGh/board-name",
        "https://notion.so/workspace/page-abc123def456",
        "https://airtable.com/appAbCdEfGhIjKlM/tblXyZaBcDeFgHiJ",
        "https://app.hubspot.com/contacts/12345/deal/67890",
        "https://app.salesforce.com/one/one.app",
        "https://monday.com/boards/1234567890",
        "https://app.clickup.com/1234567/v/l/abc-123",
        "https://linear.app/team/issue/ABC-123",
    ],
}

# ============================================================================
# 🟢 CATÉGORIE SUPPLEMENTAIRE: SERVICES FRANÇAIS COMPLEXES
# ============================================================================

FRENCH_SERVICES_COMPLEX = {
    "Services publics français complexes": [
        "https://www.impots.gouv.fr/portail/login",
        "https://ameli.fr/assure/adresse-authentification",
        "https://caf.fr/web/caf/connection",
        "https://pajemploi.urssaf.fr/pajeweb/connect",
        "https://declare.ameli.fr/assure/",
        "https://teleservice.urssaf.fr/portail/",
        "https://www.service-public.fr/compte/authentification",
        "https://mon.service-public.fr/authentification",
        "https://www.demarches-simplifiees.fr/users/sign_in",
        "https://mesdroitssociaux.gouv.fr/connexion"
    ],

    "Banques françaises sécurisées": [
        "https://www.banquepopulaire.fr/auth/oauth2/authorize",
        "https://mabanque.bnpparibas/authentification",
        "https://www.societegenerale.fr/auth/login",
        "https://www.credit-agricole.fr/authentification",
        "https://www.lcl.fr/connexion",
        "https://www.cic.fr/identification",
        "https://www.hellobank.fr/se-connecter",
        "https://www.boursorama.com/auth/login",
        "https://www.fortuneo.fr/authentification",
        "https://www.ing.fr/se-connecter"
    ]
}

# ============================================================================
# 🔴 CATÉGORIE 2: PHISHING ÉVIDENT (Doivent être PHISHING)
# ============================================================================

PHISHING_OBVIOUS = {
    "Typosquatting classique": [
        "http://gooogle.com/login",
        "https://amaz0n.com/signin",
        "http://paypa1.com/secure",
        "https://netf1ix.com/login",
        "http://facebo0k.com/signin",
        "https://app1e.com/id/signin",
        "http://micros0ft.com/login",
        "https://githb.com/login",
        "http://yah00.com/mail",
        "https://twiter.com/login",
    ],

    "Homograph/Punycode": [
        "https://xn--pple-43d.com/signin",  # аpple (cyrillic a)
        "https://xn--pypal-4ve.com/login",  # pаypal
        "https://xn--gogle-0mc.com/accounts",  # gооgle
        "https://xn--80aa.com/secure",  # caractères russes
        "https://xn--mcrsoft-8g0a.com/login",  # microsoft avec IDN
        "https://xn--mazon-1qa.com/ap/signin",  # amazon
        "https://xn--ntflix-bxa.com/login",  # netflix
        "https://xn--facebk-fyb.com/login",  # facebook
        "https://xn--githb-epa.com/signin",  # github
        "https://xn--lnkedin-s2a.com/login",  # linkedin
    ],

    "IP addresses": [
        "http://192.168.1.100/paypal/login.php",
        "https://10.0.0.50/amazon/secure/signin",
        "http://172.16.0.1/bank/login.html",
        "http://203.0.113.42/microsoft/auth",
        "https://198.51.100.89/google/accounts/signin",
        "http://45.67.89.123/netflix/login",
        "http://123.45.67.89/facebook/login.php",
        "https://98.76.54.32/apple/id/verify",
        "http://111.222.333.444/secure/login",  # IP invalide mais suspect
        "http://0x7f000001/admin/login",  # IP en hexadécimal
    ],

    "Sous-domaines suspects": [
        "https://paypal.com-secure-login.tk/verify",
        "https://amazon.com-update.ml/signin",
        "https://google.com.verify-account.ga/login",
        "https://microsoft.com-security.cf/auth",
        "https://apple.com.id-verify.gq/signin",
        "https://netflix.com-billing.xyz/update",
        "https://facebook.com-security-check.top/verify",
        "https://github.com-verify.club/login",
        "https://linkedin.com-premium.site/activate",
        "https://dropbox.com-storage.space/login",
    ],

    "TLDs suspects": [
        "https://secure-paypal.tk/signin",
        "https://amazon-login.ml/verify",
        "https://google-accounts.ga/login",
        "https://microsoft-update.cf/signin",
        "https://apple-verify.gq/id",
        "https://netflix-billing.xyz/update",
        "https://facebook-security.top/check",
        "https://bank-secure.icu/login",
        "https://verify-account.club/signin",
        "https://secure-login.download/auth",
    ],
}

# ============================================================================
# 🟡 CATÉGORIE 3: CAS LIMITES / ZONES GRISES
# ============================================================================

EDGE_CASES = {
    "Redirections légitimes": [
        "https://www.google.com/url?sa=t&url=https%3A%2F%2Fwww.example.com",
        "https://out.reddit.com/t3_abc123?url=https%3A%2F%2Fexample.com",
        "https://l.facebook.com/l.php?u=https%3A%2F%2Fexample.com",
        "https://t.co/AbCdEfGhIj",  # Twitter shortener
        "https://click.email.github.com/?qs=abc123def456",
        "https://link.mail.yahoo.com/click?data=abc123",
        "https://mandrillapp.com/track/click/xyz789",
        "https://sendgrid.net/wf/click?upn=abc123",
        "https://mailchimp.com/r/xyz789",
        "https://links.services.disqus.com/api/click?url=example.com",
    ],

    "Nouvelles startups/services (légitimes mais récents)": [
        "https://cal.com/username/30min",
        "https://vercel.app/dashboard",
        "https://railway.app/project/abc123",
        "https://replit.com/@username/project",
        "https://codesandbox.io/s/abc123",
        "https://stackblitz.com/edit/abc123",
        "https://glitch.com/edit/#!/project-name",
        "https://render.com/deploy/srv-abc123",
        "https://fly.io/apps/app-name",
        "https://deno.com/deploy/projects/abc123",
    ],

    "URLs avec mots suspects mais légitimes": [
        "https://www.paypal.com/us/smarthelp/contact-us",
        "https://www.amazon.com/gp/help/customer/account-issues",
        "https://support.google.com/accounts/answer/7682439",
        "https://account.microsoft.com/security/password/change",
        "https://appleid.apple.com/account/manage/security",
        "https://www.netflix.com/password",
        "https://www.facebook.com/help/contact/verify",
        "https://help.github.com/en/articles/securing-your-account",
        "https://www.linkedin.com/help/linkedin/answer/account-security",
        "https://help.dropbox.com/accounts-billing/security",
    ],

    "Sites d'entreprises locales (domaines non connus)": [
        "https://www.petite-entreprise-locale.fr/connexion",
        "https://www.ma-startup-innovante.com/login",
        "https://secure.banque-regionale.fr/authentification",
        "https://client.assurance-locale.com/espace-client",
        "https://www.cabinet-comptable-dupont.fr/acces-client",
        "https://portail.clinique-sante.fr/rendez-vous",
        "https://www.restaurant-lebongout.fr/reservation",
        "https://espace-client.garage-martin.fr/login",
        "https://www.avocat-durand.fr/client-portal",
        "https://booking.hotel-bellevue.fr/secure/payment",
    ],

    "URLs de test/développement légitimes": [
        "https://staging.company.com/login",
        "https://dev.application.com/auth",
        "https://beta.service.com/signin",
        "https://test.website.com/login",
        "https://demo.product.com/auth",
        "https://sandbox.api.com/oauth",
        "https://uat.platform.com/login",
        "https://preview.site.com/admin",
        "https://localhost:3000/login",
        "http://127.0.0.1:8080/admin",
    ],
}
L = []
for v in LEGITIMATE_COMPLEX.values():
    L.extend(v)
for v in FRENCH_SERVICES_COMPLEX.values():
    L.extend(v)
for v in EDGE_CASES.values():
    L.extend(v)

# L = [get_domain(i) for i in L if i not in LEGITIMATE_DOMAINS]
# print('paypal.com' in LEGITIMATE_DOMAINS)
# print(len(LEGITIMATE_DOMAINS),all(i in LEGITIMATE_DOMAINS for i in L))
# print("DÉTAILS")
# for i in L:
#     print(i in LEGITIMATE_DOMAINS)
# L = list(set(L))
# print(L,len(L))
# input()
# ============================================================================
# 🔵 CATÉGORIE 4: PHISHING SOPHISTIQUÉ (Difficiles à détecter)
# ============================================================================

PHISHING_SOPHISTICATED = {
    "Phishing avec HTTPS et certificat": [
        "https://secure-paypal-verification.com/account/review",
        "https://amazon-security-check.net/ap/signin",
        "https://google-account-recovery.org/signin/challenge",
        "https://microsoft-security-alert.com/account/verify",
        "https://apple-id-unlock.com/iforgot/verify",
        "https://netflix-payment-update.com/billing/update",
        "https://facebook-security-center.net/checkpoint",
        "https://github-security-advisory.com/login",
        "https://linkedin-premium-offer.com/activate",
        "https://dropbox-storage-upgrade.com/login",
    ],

    "Look-alike domains (très proches)": [
        "https://www.gооgle.com/accounts",  # double о (cyrillic)
        "https://www.rnicrosoft.com/login",  # rn ressemble à m
        "https://www.annazon.com/signin",  # deux n
        "https://www.paypa1.com/login",  # 1 au lieu de l
        "https://www.netfIix.com/signin",  # I majuscule au lieu de l
        "https://www.faceb00k.com/login",  # 00 au lieu de oo
        "https://www.app1e.com/id",  # 1 au lieu de l
        "https://www.githvb.com/login",  # v au lieu de u
        "https://www.linkedln.com/signin",  # ln au lieu de in
        "https://www.arnaz0n.com/ap/signin",  # 0 au lieu de o, a avant m
    ],

    "Sous-domaines trompeurs avancés": [
        "https://accounts.google.com.verify-security.online/login",
        "https://signin.microsoft.com.security-update.site/auth",
        "https://appleid.apple.com.id-verification.xyz/signin",
        "https://www.amazon.com.account-review.top/signin",
        "https://secure.paypal.com.billing-update.club/login",
        "https://login.netflix.com.payment-failed.space/update",
        "https://m.facebook.com.security-check.live/verify",
        "https://api.github.com.security-alert.tech/login",
        "https://mail.google.com.recovery-required.info/signin",
        "https://outlook.office.com.account-suspended.online/login",
    ],

    "Phishing avec redirection": [
        "https://bit.ly/paypal-urgent-action-required",  # Shortener suspect
        "https://tinyurl.com/amazon-account-suspended",
        "https://goo.gl/verify-google-account-now",
        "https://ow.ly/microsoft-security-update",
        "https://buff.ly/apple-id-verification",
        "https://shor.by/netflix-billing-problem",
        "https://clk.sh/facebook-security-check",
        "https://s.id/github-important-notice",
        "https://v.gd/linkedin-premium-trial",
        "https://is.gd/dropbox-storage-full",
    ],

    "Phishing par email (domaines de webmail)": [
        "https://webmail.company-update.com/login?ref=paypal",
        "https://mail.secure-notification.net/signin?from=amazon",
        "https://email.service-center.org/auth?alert=microsoft",
        "https://inbox.account-support.com/login?urgent=apple",
        "https://mailbox.security-team.net/verify?source=netflix",
        "https://message.billing-department.com/read?id=facebook",
        "https://notification.customer-service.org/view?alert=github",
        "https://alert.account-security.net/check?from=linkedin",
        "https://update.support-team.com/confirm?ref=dropbox",
        "https://verify.notification-center.org/action?alert=twitter",
    ],
}


# ============================================================================
# 📊 FONCTION DE TEST
# ============================================================================

def get_all_test_urls():
    """Retourne toutes les URLs de test avec leurs labels attendus"""
    all_tests = []

    # Légitimes
    for category, urls in LEGITIMATE_COMPLEX.items():
        for url in urls:
            all_tests.append({
                'url': url,
                'expected': 'safe',
                'category': f"✅ Légitime - {category}",
                'difficulty': 'medium'
            })

    # Phishing évident
    for category, urls in PHISHING_OBVIOUS.items():
        for url in urls:
            all_tests.append({
                'url': url,
                'expected': 'phishing',
                'category': f"🔴 Phishing évident - {category}",
                'difficulty': 'easy'
            })

    for category, urls in FRENCH_SERVICES_COMPLEX.items():
        for url in urls:
            all_tests.append({
                'url': url,
                'expected': 'safe',  # Ces URLs doivent être safe
                'category': f"✅ Services FR - {category}",
                'difficulty': 'medium'
            })

    # Cas limites
    for category, urls in EDGE_CASES.items():
        for url in urls:
            all_tests.append({
                'url': url,
                'expected': 'safe',  # La plupart sont légitimes
                'category': f"🟡 Cas limite - {category}",
                'difficulty': 'hard'
            })

    # Phishing sophistiqué
    for category, urls in PHISHING_SOPHISTICATED.items():
        for url in urls:
            all_tests.append({
                'url': url,
                'expected': 'phishing',
                'category': f"🔵 Phishing sophistiqué - {category}",
                'difficulty': 'very_hard'
            })

    return all_tests

def print_test_suite():
    """Affiche toutes les URLs de test organisées"""
    print("=" * 80)
    print("🧪 BATTERIE DE TESTS COMPLEXES - URLs RÉALISTES")
    print("=" * 80)

    all_tests = get_all_test_urls()

    print(f"\n📊 Total: {len(all_tests)} URLs de test")
    print(f"   - ✅ Légitimes attendues: {sum(1 for t in all_tests if t['expected'] == 'safe')}")
    print(f"   - 🔴 Phishing attendus: {sum(1 for t in all_tests if t['expected'] == 'phishing')}")

    # Grouper par difficulté
    by_difficulty = {}
    for test in all_tests:
        diff = test['difficulty']
        if diff not in by_difficulty:
            by_difficulty[diff] = []
        by_difficulty[diff].append(test)

    print("\n📈 Par difficulté:")
    for diff, tests in sorted(by_difficulty.items()):
        print(f"   - {diff}: {len(tests)} URLs")

    return all_tests

# ============================================================================
# EXPORT POUR TON CODE
# ============================================================================

if __name__ == "__main__":
    tests = print_test_suite()

    print("\n" + "=" * 80)
    print("📝 TESTE DU MODÈLE :")
    print("=" * 80)
    from main_phish import AntiPhishing
    
    def run_complete_system_test(AP):
        """Test du système complet (IA + analyse passive)"""
        tests = get_all_test_urls()
        correct = 0
        total = len(tests)
        errors = []

        for test in tests:
            result = AP.predict_url(test['url'], explain=True)

            # ✅ Décision du système COMPLET (IA + analyse passive)
            try:
                ia_pred = result['ia_pred']['predict']['0']
            except Exception:
                ia_pred = result['ia_pred']['predict'][0]
            passive_pred = result['passive_pred']['is_phishing']

            # Logique de décision finale
            if passive_pred:  # Si l'analyse passive détecte du phishing
                final_pred = 'phishing'
            else:
                final_pred = ia_pred  # On suit l'IA
            # final_pred = passive_pred or (ia_pred=='phishing')
            # final_pred = 'phishing' if final_pred else 'safe'
            if passive_pred == False or ia_pred == 'safe':
                final_pred = 'safe'
            if passive_pred == True or ia_pred == 'phishing':
                final_pred = 'phishing'
            if final_pred == test['expected']:
                correct += 1
            else:
                errors.append({
                    'url': test['url'],
                    'expected': test['expected'],
                    'got_ia': ia_pred,
                    'got_passive': 'phishing' if passive_pred else 'safe',
                    'final': final_pred,
                    'category': test['category']
                })

        print(f"🎯 Résultats SYSTÈME COMPLET: {correct}/{total} ({correct/total*100:.2f}%)")
        print(f"\\n❌ Erreurs: {len(errors)}")
        for err in errors[:10]:  # Afficher 10 premières erreurs
            print(f"  - {err['category']}")
            print(f"    URL: {err['url']}")
            print(f"    Attendu: {err['expected']}, Obtenu: {err['got_passive']}")
        return correct, total, errors

    def run_passive_only_test(AP):
        """Test UNIQUEMENT de l'analyse passive"""
        tests = get_all_test_urls()
        correct = 0
        total = len(tests)
        errors = []

        for test in tests:
            result = AP.predict_url(test['url'], explain=True)

            # ✅ UNIQUEMENT l'analyse passive
            passive_pred = result['passive_pred']['is_phishing']
            if passive_pred == False:
                final_pred = 'safe'
            else :
                final_pred = 'phishing'
            # if 'hotel-bellevue.fr' in test['url']:
                # print(result['passive_pred'])
                # print(passive_pred, final_pred)
                # input()
            if final_pred == test['expected']:
                correct += 1

            else:
                errors.append({
                    'url': test['url'],
                    'expected': test['expected'],
                    'got_passive': 'phishing' if passive_pred else 'safe',
                    'final': final_pred,
                    'category': test['category']
                })

        print(f"🎯 Résultats ANALYSE PASSIVE SEULE: {correct}/{total} ({correct/total*100:.2f}%)")
        print(f"❌ Erreurs: {len(errors)}")
        for err in errors[:10]:
            print(f"  - {err['category']}")
            print(f"    URL: {err['url']}")
            print(f"    Attendu: {err['expected']}, Obtenu: {err['got_passive']}")
        return correct, total, errors

    # Charger ton modèle
    AP = AntiPhishing('model_phish.pkl', model_dir='model',path_to_original_dataset=None)
#     import joblib
#     PH = AP.PhishingIA
#     le = PH.le
#     features_name = PH.features_name
#     model = PH.model
#     stack = model.named_steps['stack']
#     sc = model.named_steps['scaler']
#     prefit = True
#     classes_ = stack.classes_
#     stack_method_ = stack.stack_method_
#     final_estimator_ = stack.final_estimator_
#     label_encoder = stack._label_encoder
#     named_estimators_ = stack.named_estimators_
#     dic = {
#         "le":le,
#         "scaler":sc,
#         "classes_":classes_,
#         'features_name': features_name,
#         'final_estimator_':final_estimator_,
#         "named_estimators_":named_estimators_,
#         'prefit':int(prefit),
#         'stack_method_':stack_method_,
#         '_label_encoder':label_encoder
#         }
#     joblib.dump(dic,'model6_phish_new.joblib', compress=5)
#     joblib.dump(dic,'model6_phish_new.pkl', compress=5)
#     joblib.dump(dic,'model6_phish_new.json', compress=5)
    # print(AP.PhishingIA.model.named_steps['stack'].final_estimator_)
    # print()
    # input()
    # Récupérer les tests
    tests = get_all_test_urls()
    def ia_test(AP):
    # Tester
        correct = 0
        total = len(tests)
        errors = []

        for test in tests:
            result = AP.predict_url(test['url'],explain=True)#,features_func=features_extractor_from_url)
            # print(result)
            # input()
            try:
                ia_pred = result['ia_pred']['predict']['0']
            except Exception:
                ia_pred = result['ia_pred']['predict'][0]

            if ia_pred == test['expected']:
                correct += 1
            else:
                errors.append({
                    'url': test['url'],
                    'expected': test['expected'],
                    'got': ia_pred,
                    'category': test['category']
                })
#             print(result['ia_pred']['predict_proba'])
#             print(test['expected'])
        print(f"\\n🎯 Résultats: {correct}/{total} ({correct/total*100:.2f}%)")
        print(f"\\n❌ Erreurs: {len(errors)}")
        for err in errors[:10]:  # Afficher 10 premières erreurs
            print(f"  - {err['category']}")
            print(f"    URL: {err['url']}")
            print(f"    Attendu: {err['expected']}, Obtenu: {err['got']}")
    #""")

#     print("\n💾 Sauvegarder les résultats:")
#     print("""
# import json
# with open('test_results.json', 'w') as f:
#     json.dump({'correct': correct, 'total': total, 'errors': errors}, f, indent=2)
#     """)
#     run_complete_system_test(AP)
    # ia_test(AP)
    # print()
    # input()
    # run_complete_system_test(AP)
    # print()
    # input()
    run_passive_only_test(AP)
    # run_passive_only_test(AP)
    # print(AP.PassiveAnalyzer.save_domain)
