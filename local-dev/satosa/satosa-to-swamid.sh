#!/usr/bin/env bash

set -e

# Make it so we can run the script from anywhere
cd "$(dirname "$0")"

if ! [[ -v MAILTO ]]; then
    echo "missing MAILTO env variable, set it to your email address"
    exit 1
fi

DESCRIPTION="SUNET CDN - dev"
DISPLAY_NAME="SUNET CDN - dev"
INFORMATION_URL="https://github.com/SUNET/sunet-cdn-manager"
PRIVACY_STATEMENT_URL="https://www.vr.se/om-webbplatsen/behandling-av-personuppgifter.html"

satosa_metadata_file="generated/config/metadata/backend.xml"

if ! [ -f "$satosa_metadata_file" ]; then
    echo "$satosa_metadata_file does not exist, it will be created when satosa is started"
    exit 1
fi

output_xml_file="generated/sunet-cdn-satosa-metadata.xml"

# Most of the expressions (e.g. $prev) in this file is not supposed to be
# expanded by the shell but has meaning to xmlstarlet.
# shellcheck disable=SC2016 # (info): Expressions don't expand in single quotes, use double quotes for that.

xmlstarlet ed \
    -d "/ns0:EntityDescriptor/ns0:Extensions/ns2:DigestMethod[@Algorithm='http://www.w3.org/2001/04/xmldsig-more#md5']" \
    -d "/ns0:EntityDescriptor/ns0:Extensions/ns2:SigningMethod[@Algorithm='http://www.w3.org/2001/04/xmldsig-more#rsa-md5']" \
    -d "/ns0:EntityDescriptor/ns0:Extensions/ns2:DigestMethod[@Algorithm='http://www.w3.org/2000/09/xmldsig#sha1']" \
    -d "/ns0:EntityDescriptor/ns0:Extensions/ns2:SigningMethod[@Algorithm='http://www.w3.org/2000/09/xmldsig#rsa-sha1']" \
    -d "/ns0:EntityDescriptor/ns0:SPSSODescriptor/ns0:AssertionConsumerService[@Binding='urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect']" \
    -s /ns0:EntityDescriptor -t attr -n xmlns:mdattr -v "urn:oasis:names:tc:SAML:metadata:attribute" \
    -s /ns0:EntityDescriptor/ns0:Extensions -t elem -n mdattr:EntityAttributes --var ENTITY_ATTRS '$prev' \
    -s /ns0:EntityDescriptor -t attr -n xmlns:samla -v "urn:oasis:names:tc:SAML:2.0:assertion" \
    -s '$ENTITY_ATTRS' -t elem -n samla:Attribute --var SAML_ATTR '$prev' \
    -s '$SAML_ATTR' -t attr -n Name -v "http://macedir.org/entity-category" \
    -s '$SAML_ATTR' -t attr -n NameFormat -v "urn:oasis:names:tc:SAML:2.0:attrname-format:uri" \
    -s '$SAML_ATTR' -t elem -n samla:AttributeValue -v "https://refeds.org/category/personalized" \
    -s /ns0:EntityDescriptor -t elem -n ns0:Organization --var ORG '$prev' \
    -s '$ORG' -t elem -n ns0:OrganizationName -v "The Swedish Research Council" \
    -s '$prev' -t attr -n 'xml:lang' -v 'en' \
    -s '$ORG' -t elem -n ns0:OrganizationName -v "Vetenskapsrådet" \
    -s '$prev' -t attr -n 'xml:lang' -v 'sv' \
    -s '$ORG' -t elem -n ns0:OrganizationDisplayName -v "Sunet" \
    -s '$prev' -t attr -n 'xml:lang' -v 'en' \
    -s '$ORG' -t elem -n ns0:OrganizationDisplayName -v "Sunet" \
    -s '$prev' -t attr -n 'xml:lang' -v 'sv' \
    -s '$ORG' -t elem -n ns0:OrganizationURL -v "https://www.sunet.se" \
    -s '$prev' -t attr -n 'xml:lang' -v 'en' \
    -s '$ORG' -t elem -n ns0:OrganizationURL -v "https://www.sunet.se" \
    -s '$prev' -t attr -n 'xml:lang' -v 'sv' \
    -s /ns0:EntityDescriptor -t attr -n xmlns:remd -v "http://refeds.org/metadata" \
    -s /ns0:EntityDescriptor -t elem -n ns0:ContactPerson --var TECH_PERSON '$prev' \
    -s '$TECH_PERSON' -t attr -n 'contactType' -v 'technical' \
    -s '$TECH_PERSON' -t elem -n ns0:GivenName -v 'Technical' \
    -s '$TECH_PERSON' -t elem -n ns0:EmailAddress -v "mailto:$MAILTO" \
    -s /ns0:EntityDescriptor -t elem -n ns0:ContactPerson --var ADMIN_PERSON '$prev' \
    -s '$ADMIN_PERSON' -t attr -n 'contactType' -v 'administrative' \
    -s '$ADMIN_PERSON' -t elem -n ns0:EmailAddress -v "mailto:$MAILTO" \
    -s /ns0:EntityDescriptor -t elem -n ns0:ContactPerson --var SUPPORT_PERSON '$prev' \
    -s '$SUPPORT_PERSON' -t attr -n 'contactType' -v 'support' \
    -s '$SUPPORT_PERSON' -t elem -n ns0:GivenName -v 'Support' \
    -s '$SUPPORT_PERSON' -t elem -n ns0:EmailAddress -v "mailto:$MAILTO" \
    -s /ns0:EntityDescriptor -t elem -n ns0:ContactPerson --var SECURITY_PERSON '$prev' \
    -s '$SECURITY_PERSON' -t attr -n 'contactType' -v 'other' \
    -s '$SECURITY_PERSON' -t attr -n 'remd:contactType' -v 'http://refeds.org/metadata/contactType/security' \
    -s '$SECURITY_PERSON' -t elem -n ns0:GivenName -v 'Security' \
    -s '$SECURITY_PERSON' -t elem -n ns0:EmailAddress -v 'mailto:cert@sunet.se' \
    -s /ns0:EntityDescriptor -t attr -n xmlns:mdui -v "urn:oasis:names:tc:SAML:metadata:ui" \
    -s /ns0:EntityDescriptor/ns0:SPSSODescriptor/ns0:Extensions -t elem -n mdui:UIInfo --var UUINFO '$prev' \
    -s '$UUINFO' -t elem -n mdui:Description -v "$DESCRIPTION" \
    -s '$prev' -t attr -n 'xml:lang' -v 'en' \
    -s '$UUINFO' -t elem -n mdui:Description -v "$DESCRIPTION" \
    -s '$prev' -t attr -n 'xml:lang' -v 'sv' \
    -s '$UUINFO' -t elem -n mdui:DisplayName -v "$DISPLAY_NAME" \
    -s '$prev' -t attr -n 'xml:lang' -v 'en' \
    -s '$UUINFO' -t elem -n mdui:DisplayName -v "$DISPLAY_NAME" \
    -s '$prev' -t attr -n 'xml:lang' -v 'sv' \
    -s '$UUINFO' -t elem -n mdui:InformationURL -v "$INFORMATION_URL" \
    -s '$prev' -t attr -n 'xml:lang' -v 'en' \
    -s '$UUINFO' -t elem -n mdui:InformationURL -v "$INFORMATION_URL" \
    -s '$prev' -t attr -n 'xml:lang' -v 'sv' \
    -s '$UUINFO' -t elem -n mdui:PrivacyStatementURL -v "$PRIVACY_STATEMENT_URL" \
    -s '$prev' -t attr -n 'xml:lang' -v 'en' \
    -s '$UUINFO' -t elem -n mdui:PrivacyStatementURL -v "$PRIVACY_STATEMENT_URL" \
    -s '$prev' -t attr -n 'xml:lang' -v 'sv' \
    <(sed 's/<?xml version="1.0"?>/<?xml version="1.0" encoding="UTF-8"?>/' "$satosa_metadata_file") > "$output_xml_file" # set encoding, this is done so e.g. "Vetenskapsrådet" is not turned into "Vetenskapsr&#xE5;det"

echo "metadata is available in $(dirname $0)/$output_xml_file"
