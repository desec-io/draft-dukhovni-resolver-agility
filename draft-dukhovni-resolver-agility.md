%%%
Title = "Clarifications on Signature Algorithm Presence in DNSSEC Zones and Answers"
abbrev = "resolver-agility"
docname = "@DOCNAME@"
category = "std"
ipr = "trust200902"
updates = [4035]
stand_alone = "yes"
area = "Internet"
pi = ["toc", "sortrefs", "symrefs", "docmapping"]
consensus = true
workgroup = "DNSOP Working Group"
date = @TODAY@

[seriesInfo]
name = "Internet-Draft"
value = "@DOCNAME@"
stream = "IETF"
status = "standard"

[[author]]
initials = "V."
surname = "Dukhovni"
fullname = "Viktor Dukhovni"
organization = "Google LLC"
[author.address]
 email = "ietf-dane@dukhovni.org"

[[author]]
initials = "P."
surname = "Thomassen"
fullname = "Peter Thomassen"
organization = "SSE Secure Systems Engineering, deSEC"
[author.address]
 email = "peter.thomassen@securesystems.de"

[[author]]
initials = "N."
surname = "Wisiol"
fullname = "Nils Wisiol"
organization = "deSEC, Technische Universität Berlin"
[author.address]
 email = "nils@desec.io"
%%%


.# Abstract

DNSSEC ([@!RFC4035]) allows a zone to be signed with multiple signature
algorithms.
When a zone is signed with an algorithm that is also supported by a given
validating resolver, the resolver's validation strategy MUST NOT allow this
fact to be overlooked, as the resolver could otherwise be convinced to regard
the zone as "Insecure" instead of "Secure" and consequently accept unvalidated
answers (see Section 4.3 of [@!RFC4035]), rendering DNSSEC fully ineffective.
[@!RFC4035] and related documents arguably lack clarity on this palpable
requirement.
This document attempts to fill the gap by giving guidance on how to avoid such
downgrade attacks in resolver implementations [@!RFC4035].

[ Ed note: This document is being collaborated on at
<https://github.com/desec-io/draft-dukhovni-resolver-agility/>.
The authors gratefully accept pull requests. ]

{mainmatter}

# Introduction

DNSSEC (with core specifications [@!RFC4033], [@!RFC4034], [@!RFC4035],
[@!RFC6840]) employs a number of zone signing algorithms, some already obsolete,
some mainstream and mandatory to implement, and others recommended to implement,
but not yet widely deployed.
Validating resolvers generally support a range of algorithms beyond the
mandatory to implement set: Some that are deprecated, but still in use by a
non-trivial number of deployed zones, others that are expected to be in wider
use in the future.
The status of the various algorithms is noted in Section 3 of [@!RFC8624], which
is expected be updated in subsequent documents from time to time.

Some zones may be signed with multiple algorithms.  Such multi-algorithm zones
are typically in a transitional state from one algorithm to another, with at
least the new algorithm expected to be widely deployed, allowing the older
algorithm to be dropped at the end of the transition period.
(For the rollover procedure, see [@!RFC6781] Section 4.1.4.)

Algorithms that a zone is signed with are signaled via the delegation's DS
record set which is signed and published by the parent.
For each algorithm signaled this way, RRSIG signatures are expected to be
present for each record in the zone (see Section 5.11 of [@!RFC6840]).

Therefore, for a multi-algorithm zone, a resolver is expected to treat all the
mutually supported signature algorithms as equally valid, and to accept valid
signatures made via any of the supported algorithms (see Section 5.4 of
[@!RFC6840]).
This mechanism is not expected to ensure that the strongest of multiple shared
algorithms is the only one used for validation; the sole requirement is
resistance to downgrades of zones signed via a supported algorithm to
"Insecure".

A given validating resolver may not support one or more of the algorithms a zone
is signed with.
When none are supported, absent local policy requiring the zone to be signed,
the resolver MUST consider the zone "Insecure" (see Section 4.3 of [@!RFC4035]).
When, as explained in (#requirements) below, the zone's signature algorithms
overlap with those supported by the resolver, the zone MUST NOT be treated as
"Insecure" (even when no RRSIGs for supported algorithms are included in a given
reply).


## Requirements Notation

The key words "**MUST**", "**MUST NOT**", "**REQUIRED**",
"**SHALL**", "**SHALL NOT**", "**SHOULD**", "**SHOULD NOT**",
"**RECOMMENDED**", "**NOT RECOMMENDED**", "**MAY**", and
"**OPTIONAL**" in this document are to be interpreted as described in
BCP 14 [@!RFC2119] [@!RFC8174] when, and only when, they appear in all
capitals, as shown here.


{#requirements}
# Requirements on Signature Algorithms Present in DNSSEC Zones and Answers

[[ Explain algorithm agility for DS records and that if a supported combination
   of signature and hash algorithms is found there, the resolver MUST check that
   the zone apex DNSKEY RRset has at least one valid signature made with a key
   (SEP) matching a supported DS record (or any local trust anchor), otherwise the
   entire zone is "Bogus" for lack of a "Secure Entry Point" (SEP).

   The zone's candidate signing keys are then those zone apex DNSKEYs with
   protocol 3 (see Section 2.1.2 of [@!RFC4034])) and the "Zone Key" flag bit
   set (see Section 2.1.1 of [@!RFC4034]).  The zone signer MUST ensure that
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

# IANA Considerations

None

# Acknowledgements


{backmatter}


# Change History (to be removed before publication)

* draft-dukhovni-resolver-agility-00

> Initial public draft.

