/*
 * Copyright 2017-2020 AVSystem <avsystem@avsystem.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef ANJAY_INCLUDE_ANJAY_MODULES_SMS_DEFS_H
#define ANJAY_INCLUDE_ANJAY_MODULES_SMS_DEFS_H

VISIBILITY_PRIVATE_HEADER_BEGIN

/**
 * OK, so here's the thing: the maximum SMS PDU size is actually harder to
 * determine than it should be.
 *
 * C.S0004-A (which is part of the cdma2000 family of standards), section
 * 3.2.2.2.2 states that "If P_REV_IN_USE is less than seven, the base station
 * shall not assemble and transmit regular PDUs larger than 2016 bits."
 *
 * P_REV_IN_USE is the protocol revision. Revisions less than six generally
 * refer to cdmaOne (https://en.wikipedia.org/wiki/CdmaOne), a 2G standard that
 * was competing with GSM (and later 2.5G competing with GPRS and the like),
 * which was popular in some countries, especially North America and East Asia.
 * Revisions six and beyond refer to CDMA2000
 * (https://en.wikipedia.org/wiki/CDMA2000), its 3G successor which competed
 * with UMTS - later, that family of standards surrendered and CDMA networks are
 * now transitioning to LTE.
 *
 * While cdmaOne/CDMA2000 is relatively exotic compared to GSM/UMTS, this gives
 * some perspective that, at least in the 2G era from which the SMS service
 * originates, one of the standards used 2016 bits == 252 bytes. It was then
 * extended for 3G, but I wouldn't rely on the same being true for GSM/UMTS/LTE,
 * as we all know that "native" longer SMSes (that wouldn't rely on splitting
 * and concatenation) didn't really ever make it to our services.
 *
 * And it seems true - 3GPP TS 24.011 defines the air interface for SMS over
 * LTE; section 8.1.4.1 defines maximum length of RPDU as 248 octets, and
 * section 8.2.5.3 defines maximum length of TPDU as 232 octets.
 *
 * So it seems that the general consensus for maximum SMS PDU size is "256 bytes
 * minus headers", with the header size varying between air interfaces and even
 * context.
 *
 * It makes some sense, however, to have the TPDU shorter than the RPDU, as the
 * RPDU will invariably contain the SMSC number - so I'm just using the LTE
 * values.
 */

#define ANJAY_SMS_TPDU_MAX_SIZE 232
#define ANJAY_SMS_RPDU_MAX_SIZE 248

#define ANJAY_SMS_MESSAGE_MAX_SIZE 140
#define ANJAY_SMS_CONCATENATED_MESSAGE_PART_MAX_SIZE 134
#define ANJAY_SMS_CONCATENATED_MAX_PARTS 255

VISIBILITY_PRIVATE_HEADER_END

#endif /* ANJAY_INCLUDE_ANJAY_MODULES_SMS_DEFS_H */
