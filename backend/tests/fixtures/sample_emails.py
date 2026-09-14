SAMPLE_LEGITIMATE_HEADER = """Received: from mail-ed1-f65.google.com (mail-ed1-f65.google.com [209.85.208.65])
    by mx.destination.com (Postfix) with ESMTPS id 4XhG0l5v
    for <user@destination.com>; Mon, 14 Sep 2026 14:20:05 -0300
Authentication-Results: mx.destination.com;
    dkim=pass header.i=@legitcorp.com header.s=google;
    spf=pass (mx.destination.com: domain of sender@legitcorp.com designates 209.85.208.65 as permitted sender) smtp.mailfrom=sender@legitcorp.com;
    dmarc=pass (p=REJECT sp=REJECT) header.from=legitcorp.com
From: "Equipe Suporte" <sender@legitcorp.com>
To: user@destination.com
Subject: Notificação de Acesso
Date: Mon, 14 Sep 2026 14:19:50 -0300
Message-ID: <CABe_3k@mail.legitcorp.com>
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=legitcorp.com; s=google;
Return-Path: <sender@legitcorp.com>
"""

SAMPLE_PHISHING_HEADER = """Received: from bad-relay.net (bad-relay.net [185.220.101.5])
    by mx.destination.com (Postfix) with ESMTP id 12345
    for <victim@destination.com>; Mon, 14 Sep 2026 14:20:00 -0300
From: "Banco Bradesco" <seguranca@bradesc0-atualizacao.com>
Return-Path: <bounce@malicious-spammer.ru>
Reply-To: <coletor@hacker-server.cc>
Subject: URGENTE: Recadastramento de Chave
Date: Sun, 13 Sep 2026 10:00:00 -0300
Message-ID: <12345@localhost>
X-Mailer: PHPMailer 5.2.1
Content-Type: multipart/mixed; boundary="====="

--=====
Content-Type: application/octet-stream; name="comprovante.exe"
Content-Disposition: attachment; filename="comprovante.exe"
"""

SAMPLE_BEC_HEADER = """Received: from mail-relay.freeisp.org (mail-relay.freeisp.org [198.51.100.22])
    by mx.company.com with ESMTP id 998877;
    Mon, 14 Sep 2026 11:00:00 -0300
From: "Diretoria Financeira - Roberto Silva" <roberto.silva.ceo2026@gmail.com>
To: tesouraria@company.com
Reply-To: <financeiro-urgente@gmail.com>
Subject: Pagamento de Fornecedor Emergencial
Date: Mon, 14 Sep 2026 11:00:00 -0300
Message-ID: <CAFn89@mail.gmail.com>
Return-Path: <roberto.silva.ceo2026@gmail.com>
"""

SAMPLE_BOTNET_HEADER = """Received: from dynamic-pool-189-12-34.isp.net ([189.12.34.56])
    by mx.victim.com with SMTP;
    Mon, 14 Sep 2026 08:00:00 -0300
From: info@spammer.org
To: user@victim.com
Subject: Buy cheap products
Date: Mon, 14 Sep 2026 08:00:00 -0300
Message-ID: <random-botnet-id>
"""
