---
created: 2026-10-23T21:31:20 (UTC +08:00)
source: http://dde.binghamton.edu/download/stego_algorithms/
---

# Steganographic Algorithms

## Downloads

---

### Steganography

- [Steganographic Algorithms](http://dde.binghamton.edu/download/stego_algorithms)
- [Syndrome-Trellis Codes Toolbox](http://dde.binghamton.edu/download/syndrome)
- [Steganography Design](http://dde.binghamton.edu/download/stego_design)
- [Gibbs Construction in Steganography](http://dde.binghamton.edu/download/gibbs)
- [Simulator of nsF5](http://dde.binghamton.edu/download/nsf5simulator)
- [Perturbed Quantization](http://dde.binghamton.edu/download/pq)

---

### Steganalysis

- [Breaking ALASKA: Color Separation for Steganalysis in JPEG Domain](http://dde.binghamton.edu/download/alaska)
- [Feature Extractors](http://dde.binghamton.edu/download/feature_extractors)
- [Are we there yet?](http://dde.binghamton.edu/download/AreWeThereYet)
- [Ensemble Classifier](http://dde.binghamton.edu/download/ensemble)
- [Low-complexiy Linear Classifier](http://dde.binghamton.edu/download/LCLSMR)
- [LRT Linear Classifier](http://dde.binghamton.edu/download/LRT)
- [Histogram Layer](http://dde.binghamton.edu/download/model_hist)
- [Explicit Feature Maps](http://dde.binghamton.edu/download/FeaMap)
- [SPAM features](http://dde.binghamton.edu/download/spam)
- [Extractor of 274/548 Merged Features](http://dde.binghamton.edu/download/ccmerged)
- [Structural LSB Detectors](http://dde.binghamton.edu/download/structural_lsb_detectors)
- [Quantitative Steganalysis Using Rich Models](http://dde.binghamton.edu/download/quantitative_steganalysis_using_rich_models)
- [Advancing the JPEG Compatibility Attack: Theory, Performance, Robustness, and Practice](http://dde.binghamton.edu/download/jca)

---

### Digital Forensics

- [Camera Fingerprint](http://dde.binghamton.edu/download/camera_fingerprint)

---

### Image Database

- [BOSSbase 1.01](http://dde.binghamton.edu/download/ImageDB/BOSSbase_1.01.zip)
- [BURSTbase](http://dde.binghamton.edu/download/ImageDB/BURST_sorted.zip)
- [IN smart cropping](http://dde.binghamton.edu/download/ImageDB/IN_crop.zip)

# Steganographic Algorithms

This webpage was created by DDE Lab at Binghamton University, NY, in December 2012 with the intention of providing the steganography research community with Matlab, MEX and C++ implementations of steganographic algorithms for spatial domain, JPEG and Side Informed JPEG. MEX implementation usually runs faster.

DDE Lab keeps the copyright, however, the codes can be freely used for research and non-profit purposes. The full copyright notice is included in the header of all sourcecodes.

For suggestions and feedback, please use the contact information below.

Thank you.

## Contact

- [Vojtech Holub](http://dde.binghamton.edu/vholub/) - vojtech_holub (at) yahoo (dot) com
- [Vahid Sedighi](http://dde.binghamton.edu/vsedighi/) - vsedigh1 (at) binghamton (dot) edu
- [Tomas Denemark](http://dde.binghamton.edu/tomasD/) - tdenema1 (at) binghamton (dot) edu
- [Jessica Fridrich](http://www.ws.binghamton.edu/fridrich/) - fridrich (at) binghamton (dot) edu

## Spatial Domain

| Name | Matlab / MEX | C++ Win | C++ Linux | Proposed |
| --- | --- | --- | --- | --- |
| S-UNIWARD* | [S-UNIWARD.m](http://dde.binghamton.edu/download/stego_algorithms/download/S-UNIWARD_matlab.zip) | [S-UNIWARD.zip](http://dde.binghamton.edu/download/stego_algorithms/download/S-UNIWARD_windows_vc_2010_v10.zip) | [S-UNIWARD.tar.gz](http://dde.binghamton.edu/download/stego_algorithms/download/S-UNIWARD_linux_make_v10.tar.gz) | [1] |
| WOW* | [WOW.m](http://dde.binghamton.edu/download/stego_algorithms/download/WOW_matlab.zip) | [WOW.zip](http://dde.binghamton.edu/download/stego_algorithms/download/WOW_windows_vc_2010_v10.zip) | [WOW.tar.gz](http://dde.binghamton.edu/download/stego_algorithms/download/WOW_linux_make_v10.tar.gz) | [2] |
| HUGO bounding dist. | [HUGO_bounding.m](http://dde.binghamton.edu/download/stego_algorithms/download/HUGO_bounding_matlab.zip) | [HUGO_bounding.zip](http://dde.binghamton.edu/download/stego_algorithms/download/HUGO_bounding_windows_vc_2010_v10.zip) | [HUGO_bounding.tar.gz](http://dde.binghamton.edu/download/stego_algorithms/download/HUGO_bounding_linux_make_v10.tar.gz) | [3] |
| MG | [MG.zip](http://dde.binghamton.edu/download/stego_algorithms/download/MG_matlab.zip) | - | - | [7] |
| Pentary MVG | [MVG.zip](http://dde.binghamton.edu/download/stego_algorithms/download/MVG_matlab.zip) | - | - | [8] |
| MiPOD | [MiPOD.zip](http://dde.binghamton.edu/download/stego_algorithms/download/MiPOD_matlab.zip) | - | - | [10] |
| Synch | [Synch.zip](http://dde.binghamton.edu/download/stego_algorithms/download/Synch.zip) | - | - | [9] |

## JPEG

| Name | Matlab / MEX | C++ Win | C++ Linux | Proposed |  |  |
| --- | --- | --- | --- | --- | --- | --- |
| Note: Some JPEG domain steganographic algorithms implemented in Matlab require [Phil Sallee's MATLAB Jpeg Toolbox](http://www.philsallee.com/jpegtbx/index.html) (jpeg_read routine). Update: the website is no longer active. With the author's permission, we provide the copy of relevant files (including a few pre-compiled verions) [here](http://dde.binghamton.edu/download/jpeg_toolbox.zip). | Note: Some JPEG domain steganographic algorithms implemented in Matlab require [Phil Sallee's MATLAB Jpeg Toolbox](http://www.philsallee.com/jpegtbx/index.html) (jpeg_read routine). Update: the website is no longer active. With the author's permission, we provide the copy of relevant files (including a few pre-compiled verions) [here](http://dde.binghamton.edu/download/jpeg_toolbox.zip). | Note: Some JPEG domain steganographic algorithms implemented in Matlab require [Phil Sallee's MATLAB Jpeg Toolbox](http://www.philsallee.com/jpegtbx/index.html) (jpeg_read routine). Update: the website is no longer active. With the author's permission, we provide the copy of relevant files (including a few pre-compiled verions) [here](http://dde.binghamton.edu/download/jpeg_toolbox.zip). | Note: Some JPEG domain steganographic algorithms implemented in Matlab require [Phil Sallee's MATLAB Jpeg Toolbox](http://www.philsallee.com/jpegtbx/index.html) (jpeg_read routine). Update: the website is no longer active. With the author's permission, we provide the copy of relevant files (including a few pre-compiled verions) [here](http://dde.binghamton.edu/download/jpeg_toolbox.zip). | Note: Some JPEG domain steganographic algorithms implemented in Matlab require [Phil Sallee's MATLAB Jpeg Toolbox](http://www.philsallee.com/jpegtbx/index.html) (jpeg_read routine). Update: the website is no longer active. With the author's permission, we provide the copy of relevant files (including a few pre-compiled verions) [here](http://dde.binghamton.edu/download/jpeg_toolbox.zip). | Note: Some JPEG domain steganographic algorithms implemented in Matlab require [Phil Sallee's MATLAB Jpeg Toolbox](http://www.philsallee.com/jpegtbx/index.html) (jpeg_read routine). Update: the website is no longer active. With the author's permission, we provide the copy of relevant files (including a few pre-compiled verions) [here](http://dde.binghamton.edu/download/jpeg_toolbox.zip). | Note: Some JPEG domain steganographic algorithms implemented in Matlab require [Phil Sallee's MATLAB Jpeg Toolbox](http://www.philsallee.com/jpegtbx/index.html) (jpeg_read routine). Update: the website is no longer active. With the author's permission, we provide the copy of relevant files (including a few pre-compiled verions) [here](http://dde.binghamton.edu/download/jpeg_toolbox.zip). |
| J-UNIWARD* | [J-UNIWARD.m](http://dde.binghamton.edu/download/stego_algorithms/download/J-UNIWARD_matlab_v11.zip) | [J-UNIWARD.zip](http://dde.binghamton.edu/download/stego_algorithms/download/J-UNIWARD_windows_vc_2010_v11.zip) | [J-UNIWARD.tar.gz](http://dde.binghamton.edu/download/stego_algorithms/download/J-UNIWARD_linux_make_v11.tar.gz) | [1] |  |  |
| nsF5 | [nsF5_matlab.m](http://dde.binghamton.edu/download/nsf5simulator/nsf5_simulation.zip) | - | - | [4] [Details](http://dde.binghamton.edu/download/nsf5simulator) |  |  |

ORIGINAL F5 ALGORITHM AS PROPOSED IN [6]

Original Java implementation of the JPEG-domain algorithm F5 is available here: [f5_original.zip](http://dde.binghamton.edu/download/stego_algorithms/download/f5_original.zip).

Any questions regarding the code should be directed to the author: Andreas Westfeld (andreas [dot] westfeld [at] htw-dresden [dot] de), [http://www2.htw-dresden.de/~westfeld/](http://www2.htw-dresden.de/~westfeld/).

## side-informed

| Name | Matlab / MEX | C++ Win | C++ Linux | Proposed |  |  |
| --- | --- | --- | --- | --- | --- | --- |
| Note: Some JPEG domain steganographic algorithms implemented in Matlab require [Phil Sallee's MATLAB Jpeg Toolbox](http://www.philsallee.com/jpegtbx/index.html) (jpeg_read routine). Update: the website is no longer active. With the author's permission, we provide the copy of relevant files (including a few pre-compiled verions) [here](http://dde.binghamton.edu/download/jpeg_toolbox.zip). | Note: Some JPEG domain steganographic algorithms implemented in Matlab require [Phil Sallee's MATLAB Jpeg Toolbox](http://www.philsallee.com/jpegtbx/index.html) (jpeg_read routine). Update: the website is no longer active. With the author's permission, we provide the copy of relevant files (including a few pre-compiled verions) [here](http://dde.binghamton.edu/download/jpeg_toolbox.zip). | Note: Some JPEG domain steganographic algorithms implemented in Matlab require [Phil Sallee's MATLAB Jpeg Toolbox](http://www.philsallee.com/jpegtbx/index.html) (jpeg_read routine). Update: the website is no longer active. With the author's permission, we provide the copy of relevant files (including a few pre-compiled verions) [here](http://dde.binghamton.edu/download/jpeg_toolbox.zip). | Note: Some JPEG domain steganographic algorithms implemented in Matlab require [Phil Sallee's MATLAB Jpeg Toolbox](http://www.philsallee.com/jpegtbx/index.html) (jpeg_read routine). Update: the website is no longer active. With the author's permission, we provide the copy of relevant files (including a few pre-compiled verions) [here](http://dde.binghamton.edu/download/jpeg_toolbox.zip). | Note: Some JPEG domain steganographic algorithms implemented in Matlab require [Phil Sallee's MATLAB Jpeg Toolbox](http://www.philsallee.com/jpegtbx/index.html) (jpeg_read routine). Update: the website is no longer active. With the author's permission, we provide the copy of relevant files (including a few pre-compiled verions) [here](http://dde.binghamton.edu/download/jpeg_toolbox.zip). | Note: Some JPEG domain steganographic algorithms implemented in Matlab require [Phil Sallee's MATLAB Jpeg Toolbox](http://www.philsallee.com/jpegtbx/index.html) (jpeg_read routine). Update: the website is no longer active. With the author's permission, we provide the copy of relevant files (including a few pre-compiled verions) [here](http://dde.binghamton.edu/download/jpeg_toolbox.zip). | Note: Some JPEG domain steganographic algorithms implemented in Matlab require [Phil Sallee's MATLAB Jpeg Toolbox](http://www.philsallee.com/jpegtbx/index.html) (jpeg_read routine). Update: the website is no longer active. With the author's permission, we provide the copy of relevant files (including a few pre-compiled verions) [here](http://dde.binghamton.edu/download/jpeg_toolbox.zip). |
| SI-UNIWARD* | [SI-UNIWARD.m](http://dde.binghamton.edu/download/stego_algorithms/download/SI-UNIWARD_matlab_v11.zip) | [SI-UNIWARD.zip](http://dde.binghamton.edu/download/stego_algorithms/download/SI-UNIWARD_windows_vc_2010_v11.zip) | [SI-UNIWARD.tar.gz](http://dde.binghamton.edu/download/stego_algorithms/download/SI-UNIWARD_linux_make_v11.tar.gz) | [1] |  |  |
| Perturbed Quantization | [PQ_matlab.m](http://dde.binghamton.edu/download/pq/PQ_matlab.zip) | - | - | [5] [Details](http://dde.binghamton.edu/download/pq) |  |  |
| SI with Additive Distortion | [SI_additive.zip](http://dde.binghamton.edu/download/stego_algorithms/download/SI_additive.zip) | - | - | [11] |  |  |
| SI-MiPOD | [si_mipod.zip](http://dde.binghamton.edu/download/stego_algorithms/download/si_mipod.zip) | - | - | [12] |  |  |
| J2-UNIWARD | [J2_UNIWARD.m](http://dde.binghamton.edu/download/stego_algorithms/download/J2_UNIWARD.m) | - | - | [13] |  |  |
| NS in JPEG | [NS_JPEG.zip](http://dde.binghamton.edu/download/stego_algorithms/download/NS_JPEG.zip) | - | - | [14] |  |  |
| Clustered-SI (nmSI) | [nmSI_SUNI.m](http://dde.binghamton.edu/download/stego_algorithms/download/nmSI_SUNI.m) | - | - | [15] |  |  |
| PQ-UNIWARD | [PQ-UNIWARD_matlab.zip](http://dde.binghamton.edu/download/stego_algorithms/download/PQ-UNIWARD_matlab.zip) | - | - | [16] |  |  |

## Footnotes

| ∗ - | MEX and C++ implementations may contain memory leak. To avoid the problem, use 'clear mex' Matlab command after every MEX function call. If using command line, embed in smaller image batches. |
| --- | --- |

## References

[1] V. Holub, J. Fridrich, T. Denemark, Universal Distortion Function for Steganography in an Arbitrary Domain, EURASIP Journal on Information Security, (Section:SI: Revised Selected Papers of ACM IH and MMS 2013), 2014(1). [[pdf](http://dde.binghamton.edu/vholub/pdf/EURASIP14_Universal_Distortion_Function_for_Steganography_in_an_Arbitrary_Domain.pdf)]

[2] V. Holub, J. Fridrich, Designing Steganographic Distortion Using Directional Filters, IEEE Workshop on Information Forensic and Security, Tenerife, Canary Islands, December 2–5, 2012. [[pdf](http://dde.binghamton.edu/vholub/pdf/WIFS12_Designing_Steganographic_Distortion_Using_Directional_Filters.pdf)] [[poster](http://dde.binghamton.edu/vholub/pdf/WIFS12_Poster_Designing_Steganographic_Distortion_Using_Directional_Filters.pdf)]

[3] T. Filler, J. Fridrich, Gibbs Construction in Steganography, IEEE Transactions on Information Forensics and Security, December 2010. [[pdf](http://dde.binghamton.edu/filler/pdf/Fill10tifs-gibs-journal.pdf)]

[4] J. Fridrich, T. Pevný, and J. Kodovský, Statistically undetectable JPEG steganography: Dead ends, challenges, and opportunities. In J. Dittmann and J. Fridrich, editors, Proceedings of the 9th ACM Multimedia & Security Workshop, pages 3–14, Dallas, TX, September 20–21, 2007. [[pdf](http://dde.binghamton.edu/kodovsky/pdf/Fri07-ACM.pdf)]

[5] J. Fridrich, M. Goljan, and D. Soukal,Perturbed quantization steganography. ACM Multimedia System Journal, 11(2):98–107, 2005. [[pdf](http://dde.binghamton.edu/download/pq/Fri05pq.pdf)]

[6] A. Westfeld,High capacity despite better steganalysis (F5 – a steganographic algorithm). In I. S. Moskowitz, editor, Information Hiding, 4th International Workshop, volume 2137 of Lecture Notes in Computer Science, pages 289–302, Pittsburgh, PA, April 25–27, 2001. Springer-Verlag, New York.

[7] V. Sedighi, J. Fridrich and R. Cogranne,Content-Adaptive Pentary Steganography Using the Multivariate Generalized Gaussian Cover Model. Proc. SPIE, Electronic Imaging, Media Watermarking, Security, and Forensics 2015, vol. 9409, San Francisco, CA, February 8–12, 2015. [[pdf](http://dde.binghamton.edu/vsedighi/pdf/SPIE2015_Content_Adaptive_Pentary_Steganography_Using_The_Multivariate_Generalized_Gaussian_Cover_Model.pdf)]

[8] J. Fridrich and J. Kodovsky,Multivariate Gaussian model for designing additive distortion for steganography. Proc. IEEE, *ICASSP*, Vancouver, Canada, May 26-31, 2013. [[pdf](http://dde.binghamton.edu/kodovsky/pdf/ICASSP2013_Multivariate_Gaussian_model.pdf)]

[9] T. Denemark and J. Fridrich,Improving Steganographic Security by Synchronizing the Selection Channel. , 3rd IH&MMSec. Workshop, Portland, Oregon, June 17-19, 2015.

[10] V. Sedighi, R. Cogranne and J. Fridrich,Content-Adaptive Steganography by Minimizing Statistical Detectability. , IEEE Transactions on Information Forensics and Security.

[11] T. Denemark, J. Fridrich,Side-Informed Steganography with Additive Distortion. , IEEE Workshop on Information Forensic and Security, Rome, IT, November 16–19, 2015.

[12] T. Denemark, J. Fridrich,Model Based Steganography with Precover. , Proc. IS&T, Electronic Imaging, Media Watermarking, Security, and Forensics 2017, San Francisco, CA, January 29–February 2, 2017.

[13] T. Denemark, J. Fridrich,Steganography with Multiple JPEG Images of the Same Scene.,IEEE TIFS, vol. 12, no. 10, pp. 2308-2319, October 2017.

[14] T. Denemark, P. Bas, J. Fridrich,Natural Steganography in JPEG Compressed Images. , Proc. IS&T, Electronic Imaging, Media Watermarking, Security, and Forensics 2018, Burlingame, CA, 2018.

[15] Mehdi Boroumand and Jessica Fridrich,Synchronizing Embedding Changes in Side-Informed Steganography. , IS&T, Electronic Imaging, Media Watermarking, Security, and Forensics, Burlingame, CA, 2020.

[16] Jan Butora and Jessica Fridrich,Revisiting Perturbed Quantization, 9th IH&MMSec. Workshop, Brussels, Belgium, June 22-25, 2021. [[pdf](http://www.ws.binghamton.edu/fridrich/Research/dc-si-5.pdf)]

Last update: November 2015