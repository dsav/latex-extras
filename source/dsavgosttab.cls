\ProvidesClass{dsavgosttab}


% Pass any unknown option to 'scrartcl' class
\DeclareOption*{%
  \PassOptionsToClass{\CurrentOption}{eskdtab}%
}
\ProcessOptions

\DeclareRobustCommand\No\textnumero

\usepackage[utf8]{inputenc}

% This seems to silence the following babel warning:
%   No Cyrillic font encoding has been loaded so far.
%   A font encoding should be declared before babel.
%   Default `T2A' encoding will be loaded
\usepackage[T2A]{fontenc}

% Base this class on 'eskdtab' class
\LoadClass
[
  russian, utf8,
  nocolumnsxix, nocolumnxxxi, nocolumnxxxii,
  hpadding=5mm
]
{eskdtab}


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
