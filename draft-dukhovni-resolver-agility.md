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

DNSSEC [@!RFC4035] allows a zone to be signed with multiple signature
algorithms.
[@!RFC4035] specified only signer requirements for zones signed with multiple
algorithms, this document clarifies the corresponding requirements for
validating resolvers.
When the DS record set for a zone securely indicates that the zone is signed
using at least one algorithm supported by a validating resolver, the resolver
MUST avoid downgrade attacks by ensuring that authoritative RRsets from such a
zone are accompanied by at least one supported valid signature.

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
mandatory-to-implement set: Some that are deprecated, but still deployed by a
non-negligible number of live zones, and others that are expected to be in wider
use in the future.
The status of the various algorithms is noted in Section 3 of [@!RFC8624], which
is expected be updated in subsequent documents from time to time.

Some zones may be signed with multiple algorithms.  Such multi-algorithm zones
are typically in a transitional state from one algorithm to another, with at
least the new algorithm expected to be (or become) widely deployed, allowing the
older algorithm to be dropped at the end of the transition period.
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
resistance to downgrades to "Insecure" for zones signed via a supported
algorithm.

A given validating resolver may not support one or more of the algorithms a zone
is signed with.
When none are supported, absent local policy requiring the zone to be signed,
the resolver MUST consider the zone "Insecure" (see Section 4.3 of [@!RFC4035]).
But whenever the zone's signature algorithms
overlap with those supported by the resolver, the zone MUST NOT be treated as
"Insecure"; this holds even when no RRSIGs for supported algorithms are included
in a given reply.
(#requirements) below explains these requirements in greater detail.


## Requirements Notation

The key words "**MUST**", "**MUST NOT**", "**REQUIRED**",
"**SHALL**", "**SHALL NOT**", "**SHOULD**", "**SHOULD NOT**",
"**RECOMMENDED**", "**NOT RECOMMENDED**", "**MAY**", and
"**OPTIONAL**" in this document are to be interpreted as described in
BCP 14 [@!RFC2119] [@!RFC8174] when, and only when, they appear in all
capitals, as shown here.


{#requirements}
# Requirements on Signature Algorithms Present in DNSSEC Zones and Answers

To include a child domain in the parent's DNSSEC chain of trust, the parent
provides a cryptographic link to the child.
The parent does this by computing cryptographic hashes of the DNSSEC keys that
the child wishes to be included in the delegation.
As various hash digest algorithms are available, the chosen algorithm is
recorded alongside each fingerprint.
This information, together with the key's signing algorithm (and some derived
"keytag" metadata), is included in the parent zone in the form of "Delegation
Signer" (DS) records, alongside the delegation's NS (and glue) records.

Due to the degree of freedom in choosing the hash algorithm, the parent may
publish several DS records for each key (one per hash algorithm).
Typically, one or two DS records are published for a given key ([@!RFC8624]
Section 3.3).

A domain's delegation thus has at least one DS record for each child DNSSEC key
that the child has designated to be included in the delegation.
The DS record's hash digest algorithm and the associated key's signing algorithm
can easily be seen by inspection of the DS record data.

Note that the hash digest algorithm used for DS record preparation is not to be
confused with the signing algorithm of the DNSSEC key associated with that DS
record.


## Validation Requirements

To establish the DNSSEC status of a given zone, a validating resolver (absent a
local trust anchor) MUST validate the DS record set as a whole, by verifying
the RRSIG signature provided by the parent for the DS record set or its proof of
non-existence.
When that validation fails and no local trust anchor is available, the DS record
set is bad, and SERVFAIL MUST be returned. [TODO source]

If the DS record set is valid, the resolver evaluates for each DS record whether
the algorithm of the associated key (as indicated by the DS record's algorithm
field) and the hash digest algorithm (as indicated by the digest type field) are
supported.
If either (or both) are not supported, the DS record is dropped from further
consideration.
DS records that have a supported algorithm combination can be used for further
validation ("supported DS records").

When the delegation does not contain any supported DS records (and a local trust
anchor is not available), the child zone MUST be treated as "Insecure" (see
[@!RFC4035] Section 5.2 and [@!RFC6840] Section 5.2).

Otherwise, the resolver MUST check that the child zone's apex DNSKEY record set
has at least one valid signature made with a key matching a supported DS record
(or any local trust anchor).
If no such DNSKEY is found, the entire child zone is "Bogus" for lack of a
"Secure Entry Point" (SEP).
The zone SHOULD NOT be treated as "Insecure" ([@!RFC4035] Section 5). [TODO]

The zone's candidate signing keys are those zone apex DNSKEYs with the protocol
field set to 3 ([@!RFC4034] Section 2.1.2) and the "Zone Key" flag bit set
([@!RFC4034] Section 2.1.1).
Keys that do not fulfill these conditions are not signing keys and cannot be
used for validation.
(Note that the "Secure Entry Point" bit is informational only and not examined
during validation, see [@!RFC4043] Section 2.1.1.)

If validation of the DNSKEY RRset fails, queries to the entire child zone (and
DNS subtree) MUST be answered with SERVFAIL (Section 5.5 of [@!RFC4035]).
Contrariwise, when the validation of the DNSKEY RRset succeeded, all signing
keys with an algorithm supported by the validating resolver may be used to
validate records of the zone.

It is perfectly fine for the set of supported DS records to pertain to keys of
different signing algorithms.
This situation is commonly encountered during algorithm rollover ([@!RFC6781]
Section 4.1.4).

For validation of the DNSKEY and any other RRset, one valid path along supported
DS record and eligible DNSKEY as outlined above is sufficient.
Validators SHOULD accept any single valid path.
They SHOULD NOT insist that all algorithms signaled in the DS record set work,
and they MUST NOT insist that all algorithms signaled in the DNSKEY record set
work ([@!RFC6840] Section 5.11).


## Signer Requirements

The zone signer MUST ensure that each record in the zone has a signature made
with each algorithm associated with some candidate zone signing key (Section
5.11 of [@!RFC6840]).

It is possible to add algorithms at the DNSKEY that aren't in the DS record, but
not vice versa.



# Discussion

[[ This lacks accuracy / needs some more work ]]

The requirement for the signer to use all available algorithms and the requirement for the validator to accept any supported validation path enable secure algorithm rollovers. This implies that validation of a zone can happen whenever there is an intersection of the algorithm support of signer and validator.

If, in violation of the standard, a zone is not signed with all the required algorithms, it may fail validation at resolvers that only support the missing algorithms.

If, in violation of the standard, a validator insists on validating signatures for all algorithms, it may fail validation for zones that use unsupported algorithms.

If the standard was changed such that the signer is only required to sign with a single algorithm of its choice, then validators that do not support one of the algorithms used in the zone may not be able to validate the zone's RRsets. This would result in either unavailability or degrated security of the zone.


[[TODO
Random thoughts on unexpected algorithms appearing in RRSIGs. Need to reword.

> It is possible to add algorithms at the DNSKEY that aren't in the DS record, but not vice versa.

However, when "in DNSSEC mode" (i.e. there was a supported DS record, and the
DNSKEY RRset was valid), then the DNSKEY record set always contains the algorithm
of the supported DS record, and the signer MUST always have that algorithm present
for all other RRsets.
So, while the resolver SHOULD NOT enforce that all algorithms are always present:
When something seems weird and RRSIGs seem missing or have other (perhaps
unsupported) algorithms that were not present in the DS RRset, the resolver can
always take recourse with the argument that a zone or signer that does NOT
provide an RRSIG with the supported DS record's algorithm in such a case is in
violation of the RFC.
The situation is bogus because "the resolver believes there ought to be a chain
of trust".
This is a MUST, and not a contradiction to the fact that the resolver SHOULD NOT
enforce RRSIG presence for all algorithms.
In other words, even adding algorithms at the DNSKEY level is not "harmful", and
does not change the resolver's chain of trust expectations.
]]


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

