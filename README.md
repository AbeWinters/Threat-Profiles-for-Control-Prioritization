# Threat Report Analyzer
This repositoty contains a [Jupyter Notebook](./report-analyzer.ipynb) with code to analyze threat reports on threats and threat actors. The reports are in PDF format and can be found in [reports](reports), containing reports grouped per year in subfolders.

## Goals
- Determine what threats and actors are reported on within the threat report in a reproducible manner. 

## The notebook
Based on a [spreadsheet](./Threat%20reports.xlsx) build from skimming the reports, an initial list of threats and actors is compiled.
This list is used to create a basis of the possible threats and actors and the reports are scanned using these search words. The result is a generated dictionary of the number of occurences per report.

## Challenges
- A report can mention threats or actors, for example in a comparison to a previous period, but not actually report these threats as active in this period. These irrelevant threats should be left out. A way of doing this is setting a threshold on the number of hits within a report. Another way is observing the context in a sentence or paragraph in which a threat is mentioned. 
- In text, the same threats can be described using different words or even synonyms can be used. These variations should be lemmatized: Grouping together forms of a word so they can be analysed as a single item.
- Where some reports are short and to the point, others are more lenghty and contain lot's of text. Therefore the number of hits should be normalized.

