# Options for the notebooks
The notebooks contain various settings that can be changed, with the main options being the sector, control framework and time frame.

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
The following 42 sectors are included within ETDA:
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