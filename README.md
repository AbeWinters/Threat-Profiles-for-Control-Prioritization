# Threat Report Analyzer
This repositoty contains a [Jupyter Notebook](./report-analyzer.ipynb) with code to analyze threat reports on threats and threat actors. The reports are in PDF format and can be found in [reports](reports), containing reports grouped per year in subfolders.
The end goal is to generate a threat profile for an industry with prioritized actors and TTPs, and use this to prioritize security controls.

## High level overview
![high level overview](./docs/images/High%20level%20methodology.png)

## Installation
To run the notebooks, clone this repository and install the required packages using:

`pip install -r requirements.txt`

## The notebooks
Based on the three methods from the thesis, three models will be tested. 
At first, the skimming method is implemented based on the resulting [spreadsheet](./Threat%20reports.xlsx) build from skimming the reports.
This list is used to create a basis of the possible threats and actors and the reports are scanned using these search words. The result is a generated dictionary of the number of occurences per report. This is further enhanced with data from public sources to rank actors and ttps, and finally prioritize controls. This pipeline can be found in [01. Manual extraction.ipynb](./01.%20Manual%20extraction.ipynb)

## Sources
This repository makes use of the following sources:
- [MITRE ATT&CK](https://attack.mitre.org/). To access the data, their [attackcti](https://attackcti.com/intro.html) package is used. 
- [ETDA](https://apt.etda.or.th/cgi-bin/aptgroups.cgi)
- tropChaud's [Categorized Adversary TTPs](https://github.com/tropChaud/Categorized-Adversary-TTPs).

## Challenges
- A report can mention threats or actors, for example in a comparison to a previous period, but not actually report these threats as active in this period. These irrelevant threats should be left out. A way of doing this is setting a threshold on the number of hits within a report. Another way is observing the context in a sentence or paragraph in which a threat is mentioned. 
- In text, the same threats can be described using different words or even synonyms can be used. These variations should be lemmatized: Grouping together forms of a word so they can be analysed as a single item.
- Where some reports are short and to the point, others are more lenghty and contain lot's of text. Therefore the number of hits should be normalized.

