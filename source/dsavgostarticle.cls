\ProvidesClass{dsavgostarticle}


% Pass any unknown option to 'scrartcl' class
\DeclareOption*{%
  \PassOptionsToClass{\CurrentOption}{eskdtext}%
}
\ProcessOptions

% Base this class on 'eskdtext' class
\LoadClass
[
  russian, utf8, 12pt,
  nocolumnsxix, nocolumnxxxi, nocolumnxxxii,
  hpadding=5mm
]
{eskdtext}


% Common setup
\input{dsavbasearticle.inc}


%% Fonts
\setseriffontfamily{CMU Serif}
\setsansfontfamily{CMU Sans Serif}
\setmonofontfamily{CMU Typewriter Text}


% Spacing
\setlinespacing{1.15}
\setparagraphindent{2em}


\setfloatslabelseparator{emdash}


%% Cyrillic special for ESKD
%% Also ESKD uses Babel, so no Polyglossia here
\RequirePackage{xecyr}
\RequirePackage{xltxtra}


%% Italic everywhere in ESKDX
\renewcommand{\ESKDfontShape}{\sffamily\itshape}


% Show only sections and subsections in TOC
\RequirePackage{titletoc}
\setcounter{tocdepth}{2}


%% Adjust sections and paragraphs styles and vertical margins
\ESKDsectSkip{section}{3.5ex}{3.0ex}
\ESKDsectSkip{subsection}{2.5ex}{2.5ex}
\ESKDsectSkip{subsubsection}{2.5ex}{2.5ex}
\ESKDsectStyle{section}{\Large\bfseries\uppercase}
\ESKDsectStyle{subsection}{\Large\bfseries}
\ESKDsectStyle{subsubsection}{\large\bfseries}
\renewcommand\paragraph
{
  \@startsection{subparagraph}{4}{\parindent}
    {2.5ex}{2.5ex}
    {\normalfont\normalsize\bfseries}
}
\renewcommand\subparagraph
{
  \@startsection{subparagraph}{5}{\parindent}
    {2.5ex}{2.5ex}
    {\normalfont\small\bfseries}
}


% Start every section from new page
\let\stdsection\section
\renewcommand\section{\clearpage\stdsection}


% GOST UTF-8 custom style for listing literature
\bibliographystyle{utf8gost71u}


% Make font used in main inscription smaller
\renewcommand{\ESKDfontVII}{\ESKDfontV}


%% \inputtitle{file}    Inputs title from one-page pdf file
%% Usage                \inputtitle{title.pdf}
\newcommand{\inputtitle}[1]
{
  \ESKDthisStyle{title}
  \includepdf[pages=-]{title.pdf}
}


% Redefine \tableofcontents so that it has inscription and its page number is 3
\let\originaltableofcontents\tableofcontents
\renewcommand{\tableofcontents}
{
    
    \setcounter{page}{3}
    \ESKDthisStyle{formII}
    \originaltableofcontents
}


% Patched version of eskdstamp.sty is required in order to implement
% \ESKDinscriptedappendix. See eskdstamp.sty and eskdstamp.sty.diff for
% details.

%% \ESKDinscriptedappendix{type}{title}  Places an inscripted appendix of type 'type'
%%                                       and with title 'title'.
%%                                       'Inscripted' means there is an inscription
%%                                       frame on the appendix page
%%
%% Usage                \ESKDinscriptedappendix{Обязательно}{UML-диаграмма}
\newcommand{\ESKDinscriptedappendix}[2]
{%
  \ESKDclearDoublePage%
  \refstepcounter{appendix}%
  \setcounter{point}{0}%
  \ifESKD@point@style@single%
    \renewcommand{\thepoint}{\theappendix.\arabic{point}}%
  \fi
  \setcounter{section}{0}%
  \renewcommand{\thesection}{\theappendix.\arabic{section}}%
  \setcounter{equation}{0}%
  \renewcommand{\theequation}{\theappendix.\arabic{equation}}%
  \setcounter{figure}{0}%
  \renewcommand{\thefigure}{\theappendix.\arabic{figure}}%
  \setcounter{table}{0}%
  \renewcommand{\thetable}{\theappendix.\arabic{table}}%
  \addcontentsline{toc}{section}{\appendixname\ \theappendix\ #2}%
  \begin{list}{}{%
    \setlength{\itemindent}{0mm}%
    \setlength{\labelwidth}{0mm}%
    \setlength{\labelsep}{0mm}%
    \setlength{\leftmargin}{0mm}%
    \setlength{\topsep}{0mm}%
    \setlength{\parskip}{0mm}%
    \setlength{\partopsep}{0mm}%
    \setlength{\itemsep}{0mm}%
    \setlength{\parsep}{0mm}}
    \item\centering\appendixname\ \theappendix
    \ifx#1\@empty\else\\(#1)\fi\\
  \end{list}%
  \par\nobreak\addvspace{\ESKDappendixSkip}
  \ESKDthisStyle{formII}  
  \ESKDcolumnI{#2}
}


%% \ESKDuninscriptedappendix{type}{title}  Places an uninscripted appendix of type
%%                                         'type' and with title 'title'.
%%
%% Usage                \ESKDuninscriptedappendix{Обязательно}{UML-диаграмма}
\let\ESKDuninscriptedappendix\ESKDappendix


%% \setappendicesinscripted   Makes \ESKDappendix an alias to ESKDinscriptedappendix
%% Usage                      \ESKDappendix{Обязательно}{UML-диаграмма}
\newcommand{\setappendicesinscripted}
{
    \let\ESKDappendix\ESKDinscriptedappendix
}


%% \setappendicesuninscripted   Makes \ESKDappendix an alias to ESKDuninscriptedappendix
%% Usage                        \ESKDappendix{Обязательно}{UML-диаграмма}
\newcommand{\setappendicesuninscripted}
{
    \let\ESKDappendix\ESKDuninscriptedappendix
}
