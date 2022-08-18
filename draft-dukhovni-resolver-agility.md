---
title: "Validating DNSSEC resolver algorithm agility clarifications"
abbrev: title
docname: draft-dukhovni-resolver-agility-00
category: std
ipr: trust200902
updates: 4035
stand_alone: yes
pi: [toc, sortrefs, symrefs, docmapping]
consensus: true

author:
  -
    ins: V. Dukhovni
    name: Viktor Dukhovni
    org: Google LLC
    email: ietf-dane@dukhovni.org

normative:
  RFC4034:
  RFC4035:
  RFC5155:


--- abstract

DNSSEC {{RFC4035}} employs a number of zone signature algorithms.  When a zone
is signed with an algorithm that is also supported by a given validating
resolver, it MUST NOT be possible to hide this fact from the resolver and
thereby convince it to accept unvalidated answers, i.e. downgrade the zone from
"Secure" to "Insecure" (see section 4.3 of {{RFC4035}}).  How to avoid such
downgrades in resolvers is not adequately covered in {{RFC4035}}, this document
attempts to fill the gap.

--- middle

# Introduction

DNSSEC {{RFC4035}} employs a number of zone signing algorithms, some already
obsolete, some mainstream and mandatory to implement, and others recommended to
implement, but not yet widely deployed.  Validating resolvers generally support
a range of algorithms beyond the mandatory to implement set.  Some that are
deprecated, but still in use by a non-trivial number of deployed zones, others
that are expected to be in wider use in the future.  The status of the various
algorithms is noted in Section 3 of {{RFC8624}}, which is expected be updated
in subsequent documents from time to time.

Some zones may be signed with multiple algorithms.  Such multi-signed zones are
typically in a transitional state from one algorithm to another, with at least
the new algorithm expected to be widely deployed, allowing the older algorithm
to be dropped at the end of the transition period.

Therefore, when a zone is multi-signed, a resolver is expected to treat all
the mutually supported signature algorithms as equally valid, and to accept
valid signatures made via any of the supported algorithms.  This form of
*algorithm agility* is not expected to ensure that the *strongest* of multiple
shared algorithms is the only one used for validation, the sole requirement is
resistance to downgrades of zones signed via a supported algorithm to
"Insecure".

One or more algorithms with which a zone is signed may not be supported by a
given validating resolver, and when none are supported, absent local policy
requiring the zone to be signed, the resolver MUST consider the zone "Insecure"
(see Section 4.3 of {{RFC4035}}).  When, as explained in {{Algorithm agility}}
below, the zone's signature algorithms overlap with those supported by the
resolver, the zone MUST NOT be treated "Insecure" (even when no RRSIGs for
supported algorithms are included in a given reply).


## Requirements Notation

   The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
   "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY",
   and "OPTIONAL" in this document are to be interpreted as described
   in BCP 14 {{RFC2119}} {{RFC8174}} when, and only when, they appear
   in all capitals, as shown here.

# Algorithm agility

[[ Explain algorithm agility for DS records and that if a supported combination
   if signature and hash algorithms is found there, the resolver MUST check that
   the zone apex DNSKEY RRset has at least one valid signature made with a key
   (SEP) matching a supported DS record (or any local trust anchor), otherwise the
   entire zone is "Bogus" for lack of a "Secure Entry Point" (SEP).

   The zone's candidate signing keys are then those zone apex DNSKEYs with
   protocol 3 (see section 2.1.2 of {{RFC4035}})) and the "Zone Key" flag bit
   set (see section 2.1.1 of {{RFC4035}}).  The zone signer MUST ensure that
   each record in the zone has a signature made with each algorithm associated
   with some candidate zone signing key.

   The requirements on the validating resolver are somewhat less strict, if the
   zone is not "Insecure", for lack of a supported DS record in the parent zone
   (or a alternatively a local trust anchor), then the resolver MUST only require
   that at least one supported validatable RRSIG sign each RRset for which the zone
   is authoritative (i.e. everything other than delegation NS and glue address
   records).

   This means that a resolver SHOULD accept a response signed with only a subset
   of the required signature algorithms, so long at least one of these signatures
   is supported and valid (passes signature validation, is not expired and made by
   a candidate key).

   If a zone is not signed with all the required algorithms, it may appear "Bogus"
   to resolvers that only support the missing algorithms, so all the required
   signatures MUST be present, but resolvers SHOULD NOT enforce this.
   ... ]]


# Security Considerations

This entire document discusses security considerations relating to avoiding
DNSSEC downgrades to "Insecure".

# Operational Considerations

# IANA Considerations

None.

--- back

# Acknowledgments
