%%%
Title = "Clarifications on Signature Algorithm Presence in DNSSEC Zones and Answers"
abbrev = "resolver-agility"
docname = "@DOCNAME@"
category = "std"
ipr = "trust200902"
updates = [4035,6840]
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

DNSSEC (RFC 4035) allows a zone to be signed with multiple signature
algorithms.
RFC 4035 specified only signer requirements for zones signed with multiple
algorithms, this document clarifies the corresponding requirements for
validating resolvers.
When the DS record set for a zone securely indicates that the zone is signed
using at least one algorithm supported by a validating resolver, the resolver
MUST avoid downgrade attacks by ensuring that authoritative RRsets from such a
zone are accompanied by at least one supported valid signature.

This document updates RFCs 4035 and 6840 with relaxed DNSKEY and RRSIG inclusion
requirements for signers, and more explicit requirements for validators.

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
mandatory-to-implement set: some that are deprecated, but still deployed by a
non-negligible number of live zones, and others that are expected to be in wider
use in the future.
The status of the various algorithms is noted in Section 3 of [@!RFC8624], which
is expected be updated in successor documents from time to time.

Some zones may be signed with multiple algorithms.  Such multi-algorithm zones
are typically in a transitional state from one algorithm to another, with at
least the new algorithm expected to be (or become) widely deployed, allowing the
older algorithm to be dropped at the end of the transition period.
(For the rollover procedure, see [@?RFC6781] Section 4.1.4.)

Therefore, for a multi-algorithm zone, a resolver is expected to treat all the
mutually supported signature algorithms as equally valid, and to accept valid
signatures made via any of the supported algorithms (see Section 5.4 of
[@!RFC6840]).
This mechanism is not expected to ensure that the strongest of multiple shared
algorithms is the only one used for validation; the sole requirement is
resistance to downgrades to "Insecure" for zones signed via a supported
algorithm.

The algorithms that a zone is signed with are signaled via the delegation's DS
record set which is signed and published by the parent.  For each algorithm
signaled this way, RRSIG signatures are expected to be present for each
authoritative RRSet in the zone (see Section 5.11 of [@!RFC6840]).

A given validating resolver may not support one or more of the algorithms a zone
is signed with.
When none are supported, absent local policy requiring the zone to be signed,
the resolver MUST consider the zone "Insecure" (see Section 4.3 of [@!RFC4035]).
But whenever the zone's signature algorithms
overlap with those supported by the resolver, the zone MUST NOT be treated as
"Insecure"; this holds even when no DNSKEYs or RRSIGs for supported algorithms
are included in a given reply.
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

To extend a parent domain's DNSSEC chain of trust to a delegated child domain,
the parent publishes a signed (with the parent zone's keys) list of
cryptographic fingerprints and associated metadata of the child domain's
trusted signing keys.  As various hash algorithms are supported, the one used
for a given key is recorded alongside its fingerprint.  The hash algorithm and
value, together with the key's signing algorithm (and the derived "keytag"),
are included in the parent zone in the form of "Delegation Signer" (DS)
records, alongside the delegation's NS (and glue) records.

A single DS hash algorithm may not be sufficient to cover all resolvers.  Older
resolvers may lack support for new hash algorithms, and newer resolvers may
have dropped support for outdated hash algorithms.  Therefore, the parent zone
may publish several DS records for the same key (one per hash algorithm).
Typically, one or two DS records are published for a given key ([@!RFC8624]
Section 3.3).

Note that the hash algorithm used for DS record preparation is not to be
confused with the signing algorithm of the DNSSEC key associated with that DS
record, or any hash algorithm used as part of the signing algorithm of the
DNSSEC key associated with that DS record.  For example, a DS record that
hashes the key with SHA2-256 may correspond to an RSASHA512(10) key, which
creates signatures via RSA with SHA2-512.

{#signer}
## Signer Requirements

The zone's candidate signing keys are those zone apex DNSKEYs with the protocol 
field set to 3 ([@!RFC4034] Section 2.1.2) and the "Zone Key" flag bit set 
([@!RFC4034] Section 2.1.1).  Keys that do not fulfill these conditions are not
signing keys and cannot be used for validation.  (Note that the "Secure Entry
Point" bit is informational only and not examined during validation, see
[@!RFC4034] Section 2.1.1.)

[@!RFC4035] Section 2.2 and [@!RFC6840] Section 5.11 mandate that for each
DNSSEC algorithm listed in the parent DS RRset there be at least one DNSKEY of
the same algorithm in the child apex DNSKEY RRSet.  Implicit, but unstated, is
the requirement that such a key MUST actually match a corresponding DS record,
and must sign the DNSKEY RRSet.  In other words, for each algorithm
in the parent DS RRSet there must be a child DNSKEY that is a "secure entry
point" into the child zone (such a key will typically, but need not, have the
SEP bit set).  This makes it possible for a resolver that supports that
algorithm (and none of the other designated algorithms) to build a trust chain
to the child zone.

[@!RFC4035] Section 2.2 and [@!RFC6840] Section 5.11 also mandate that there
MUST be an RRSIG for each RRset using at least one DNSKEY of each algorithm in
the zone apex DNSKEY RRset.  This requirement is relaxed in this document to
apply to only the algorithms listed in the parent DS RRset.  Algorithms that
appear only in the child zone apex DNSKEY RRSet do not need to be used to sign
the zone.  Note however, that for some time (DS TTL + secondary server
replication delay) after an algorithm is dropped from the parent DS RRset, some
resolvers may still have cached copies that list that algorithm, so the
associated RRSIGs need to be retained until all such copies expire.

{#dnskey}
### Inclusion of DNSKEY Records

The zone signer MUST ensure that

  - For each DNSKEY algorithm listed in at least one parent DS record (or used
    as part of a trust anchor set), at least one DNSKEY of that algorithm is a
    "secure entry point into" the zone.  In other words, that DNSKEY is matched
    by a parent DS record, isn't revoked, and the child zone apex DNSKEY RRset
    is accompanied by a RRSIG under that key.

  - For each DNSKEY algorithm listed in at least one parent DS record (or used
    as part of a trust anchor set), at least one DNSKEY listed in the thus
    validated child zone DNSKEY RRset, signs each of the authoritative RRsets
    in the child zone.  Different RRsets may be signed with different keys.

Note that this relaxes the previous requirement to have a signature from every
algorithm listed in the DNSKEY RRset.  Algorithms that appear only the DNSKEY
RRset, but not in the parent DS (or as part of a trust anchor set) don't have to
be used to sign any zone data.

{#validator}
## Validator Requirements

This section updates RFC 4035 to clarify the required validation behavior.

### DS Validation and Processing

A validating resolver MUST determine the provenance (associated zone) of each
RRset returned in the answer and authority sections of its response and whether
that zone is "Secure" or "Insecure".

    - If the RRset is from a zone for which it is authoritative, whether it
      is "Secure" is determined via local configuration.  The resolver need not
      perform DNSSEC validation of authoritative RRsets, but does need to
      locate and return the requisite RRSIG, NSEC or NSEC3 records in its
      response when the request had the DO bit set.
      [ TODO: What about the AD bit in this case? Can it be set if DNSSEC
      records returned upon DO request may conflict (as validation is skipped? ]

    - Otherwise, if the zone has (by local policy) a negative trust anchor,
      or if the zone is the root zone but has no trust anchor configured,
      then the zone is "Insecure".

    - Otherwise, if the RRset is from a zone with an associated trust anchor
      set and at least one DNSKEY algorithm in the trust anchor set is
      supported, the zone is "Secure".  Its DNSKEY RRSet MUST be signed with
      at least one of the trust anchor keys.
      [ TODO: The last sentence sounds like a signer requirement. ]
      [ TODO: Does this MUST also hold when the parent is Secure and has DS? ]

    - Otherwise, if the RRset is from a zone delegated from a "Secure" parent,
      its security status is determined from the signed presence of the
      associated DS RRset or its signed denial of existence by that parent.
      Explicit probing for the DS RRSet may be needed in some cases, notably
      when the same nameserver handles both the parent and child zone.
      [ TODO: When is that not required? ]

        * If a valid DS RRset is obtained, and at least one record designates a
          supported DNSKEY algorithm with a supported hash type, then the
          associated zone is also "Secure".  If either (or both) are not
          supported, the DS record in question is dropped from further
          consideration.  DS records that have a supported algorithm
          combination can be used for further validation ("supported DS
          records").

        * If a valid denial of existence is obtained, then the associated zone
          is "Insecure".

        * If neither the DS RRset or its denial of existence can be validated,
          the delegation is "Bogus" and a SERVFAIL must be returned to the
          client.

    - Otherwise, if the RRset is in zone that is delegated from an "Insecure"
      parent, then the child zone MUST also be treated as "Insecure" (see
      [@!RFC4035] Section 5.2 and [@!RFC6840] Section 5.2).

### DNSKEY Validation and Processing

Except when answering authoritatively from local zone data, if a zone's status
is "Secure", the resolver MUST check that the zone's apex DNSKEY record set has
at least one valid signature made with a DNSKEY matching a supported DS record
(or any local trust anchor).  If no such DNSKEY is found or if validation of
the DNSKEY RRset fails, the entire child zone is "Bogus" for lack of a "Secure
Entry Point" (SEP).  Queries to the entire child zone (and DNS subtree) MUST be
answered with SERVFAIL (Section 5.5 of [@!RFC4035]).  The zone MUST NOT be
treated as "Insecure".

Contrariwise, when the validation of the DNSKEY RRset succeeded, all the
contained supported keys with the "ZONE" bit set that are not revoked are valid
signing keys of zone data.  Any such key (there's at least one) may be used to
validate RRsets of the zone, including keys not directly referenced by or
whose algorithm does not appear in the DS RRset (or trust anchor set).


# Discussion

[[ This lacks accuracy / needs some more work ]]

Random thoughts:

It is possible to add algorithms at the DNSKEY that aren't in the DS RRset, but
not vice versa.

(Root) trust anchor pre-publication


## Validation when Multiple DS Records are Present

It is perfectly fine for the set of supported DS records to pertain to keys of
different signing algorithms.  This situation is commonly encountered during
algorithm rollover ([@?RFC6781] Section 4.1.4).

For validation of the DNSKEY and any other RRset, one valid path along
supported DS record and eligible DNSKEY as outlined above is sufficient.
Validators MUST accept any single valid path.  They MUST NOT insist that all
[ TODO: This updates previous spec and should be pointed out in abstract. Also,
  we should give a rationale for the change. ]
algorithms signaled in the DS record set work, and they MUST NOT insist that
all algorithms signaled in the DNSKEY record set work ([@!RFC6840] Section
5.11).

More colloquially, validators MUST NOT apply a "logical AND" requirement on all
validation paths offered by the DS record set; instead, employing a "logical OR"
validation strategy is required.

However, this does not mean that there is an expectation that any specific DS
record provides a working path: the DS RRset may reference several keys of the
same signing algorithm, with only one of them signing the DNSKEY RRset, and
others pointing "nowhere" (no corresponding DNSKEY).  That said, such
"dangling" DS records are best avoided.  It is best practice, and should
generally be possible to publish DNSKEYs sufficiently in advance of the
matching DS records, and to remove the matching DS RR well before the DNSKEY is
dropped.

## Validation when unsupported DNSSEC Records are Present

DS/DNSKEY records with unsupported algorithms MUST NOT affect validation.

Excess RRSIGs (with unsupported algorithm numbers) MUST NOT affect validation.

If, in violation of the requirements, a zone is not signed with all the
required algorithms, it may fail validation at resolvers that only support the
missing algorithms.

If, in violation of the requirements, a validator insists on validating
signatures for all algorithms, it may fail validation for zones that use
unsupported algorithms.


# Security Considerations

This entire document discusses security considerations relating to avoiding
DNSSEC downgrades to "Insecure".

# IANA Considerations

None

# Acknowledgements

Edward Lewis, Jakob Schlyter, Johan Stenstam


{backmatter}


# Motivation

[[ TODO Mention validation bugs related to unclear rules, such as 1.1.1.1 / 8.8.8.8 incorrect "insecure" responses in 2022. ]]


# Change History (to be removed before publication)

* draft-dukhovni-resolver-agility-00

> Initial public draft.
