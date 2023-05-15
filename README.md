# Control prioritization using sector-based threat profiles
This repositoty contains various notebooks with code to analyze determine active threat actors targeting a sector. Based on their used TTPs, controls will be prioritized. 
The notebooks contain various approaches to reach this goal, and are part of the masters thesis of Abe Winters.
The current control frameworks implemented are:
- NIST SP 800-53 rev.5

## High level overview
![high level overview](./docs/images/High%20level%20methodology.png)

## Installation
To run the notebooks, clone this repository and install the required packages using:

`pip install -r requirements.txt`

## The notebooks
Based on the three methods from the thesis, three models will be tested. 
At first, the skimming method is implemented based on the resulting [spreadsheet](./Threat%20reports.xlsx) build from skimming the reports. 
The reports are in PDF format and can be found in [reports](reports), containing reports grouped per year in subfolders.
This list is used to create a basis of the possible threats and actors and the reports are scanned using these search words. The result is a generated dictionary of the number of occurences per report. This is further enhanced with data from public sources to rank actors and ttps, and finally prioritize controls. This pipeline can be found in [Method 1.ipynb](./Method%201.ipynb)

The second method is based on operation dates. An interval can be selected, and actors are retrieved based on their activity within that period. The actor weights are determined by the amount of activity within the timeframe. The pipeline can be found in [Method 2.ipynb](./Method%202.ipynb). A future addition to the actor weight function is weighing recent operations heavier than other operations.

## Mappings
Within the [mappings](./data/mappings/) folder exist spreadsheets containing mappings to and from control frameworks. The notebook [attck-nist-mappings.ipynb](./data/mappings/attck-nist-mappings.ipynb) explores mappings between MITRE ATT&CK and NIST SP-800 53 r5. The notebook [cis-mappings.ipynb](./data/mappings/cis-mappings.ipynb) creates mappings by leveraging the CIS Controls, since there exist many mappings to and from this control set.

## Sources
This repository makes use of the following sources:
- [MITRE ATT&CK](https://attack.mitre.org/). To access the data, their [attackcti](https://attackcti.com/intro.html) package is used. 
- [ETDA](https://apt.etda.or.th/cgi-bin/aptgroups.cgi)
- tropChaud's [Categorized Adversary TTPs](https://github.com/tropChaud/Categorized-Adversary-TTPs). This code has been edited to include the full ETDA dataset and include activity dates.

## Challenges
- A report can mention threats or actors, for example in a comparison to a previous period, but not actually report these threats as active in this period. These irrelevant threats should be left out. A way of doing this is setting a threshold on the number of hits within a report. Another way is observing the context in a sentence or paragraph in which a threat is mentioned. 
- In text, the same threats can be described using different words or even synonyms can be used. These variations should be lemmatized: Grouping together forms of a word so they can be analysed as a single item.
- Where some reports are short and to the point, others are more lenghty and contain lot's of text. Therefore the number of hits should be normalized.

