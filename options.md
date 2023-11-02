# Options for the notebooks

The notebooks contain various parameters that can be changed, with the main options being the sector, control framework and time frame.
Filtering on victim country and motivation are optional and can be disabled by setting their respective flags to `False`.

The following settings can be tweaked:

- [Time Frame](#time-frame)
- [Control Set](#control-set)
- [Sector](#sectors)
- [Victim country](#country)
- [Threat Actor Motivation](#motivation)

## Time Frame

For the operation method in Method 3, an interval can be selected by setting `YEAR` and `INTERVAL`. The resulting interval is the period between `YEAR - INTERVAL` and `YEAR`

## Control set

The following control sets are supported:

| Standard             | Option         | Comment                                                                         |
|----------------------|----------------|---------------------------------------------------------------------------------|
| NIST SP 800-53 rev.5 | NIST_SP_800_53 |                                                                                 |
| NIST CSF             | NIST_CSF       |                                                                                 |
| CIS v8               | CIS_v8         |                                                                                 |
| ISO 27001:2022       | ISO_2022       |                                                                                 |
| ISO 27001:2013       | ISO_2013_CIS   | Since it is an indirect mapping, this mapping is done via CIS v8                |
| ISO 27001:2013       | ISO_2013_NIST  | Since it is an indirect mapping, this mapping is done via NIST SP 800-53 rev. 5 |

## Sectors

The following 42 sectors are included within ETDA and can be used as a value for the `Sector` parameter:

- Aerospace
- Automotive
- Aviation
- Casinos and Gambling
- Chemical
- Construction
- Critical infrastructure
- Defense
- Education
- Embassies
- Energy
- Engineering
- Entertainment
- Financial
- Food and Agriculture
- Gaming
- Government
- Healthcare
- High-Tech
- Hospitality
- IT
- Industrial
- Law enforcement
- Manufacturing
- Maritime and Shipbuilding
- Media
- Mining
- NGOs
- Non-profit organizations
- None Provided
- Oil and gas
- Online video game companies
- Petrochemical
- Pharmaceutical
- Research
- Retail
- Satellites
- Shipping and Logistics
- Technology
- Telecommunications
- Think Tanks
- Transportation
- Utilities

## Country

If the `FILTER_COUNTRY` flag is set to `True`, the results will be filtered on the *victim country* specified in `COUNTRY`.
Write the country in full, starting with a capital. Some examples:

- Netherlands
- 

## Motivation

If the `FILTER_MOTIVATION` flag is set to `True`, the results will be filtered on the *threat actor motivation* specified in `MOTIVATION`.
The following options are available:

- Financial crime'
- Financial gain',
- Information theft and espionage
- Sabotage and destruction
