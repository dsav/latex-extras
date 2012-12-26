\ProvidesClass{dsavarticle}

% Base this class on 'scrartcl' class

\DeclareOption*{
  \PassOptionsToClass{\CurrentOption}{scrartcl}
}
\ProcessOptions

\LoadClass[a4paper, 12pt]{scrartcl}


% Use additional math features.
%   'XXXXlimits' is to place subscripts and superscripts for integrals, sums etc.
%   above and below in displayed equations, not somewhere to the right
\RequirePackage[sumlimits, intlimits, namelimits]{amsmath}


\input{dsavbasearticle.inc}


% Configure math font
\RequirePackage{unicode-math}

%% \setmathfontfamily{font}     Sets document math font to 'font'
%% Usage                        \setmathfontfamily{Asana Math}
\newcommand{\setmathfontfamily}[1]
{
    \setmathfont[range = \mathit]{#1}
    \setmathfont[Scale = MatchLowercase]{#1}
}


% Fonts
\setseriffontfamily{Linux Libertine}
\setsansfontfamily{PT Sans}
\setmonofontfamily{Droid Sans Mono}
\setmathfontfamily{Asana Math}


% Spacings
\setlinespacing{1.15}
\setparagraphindent{2em}
\geometry
{
  left   = 2cm,
  right  = 2cm,
  top    = 1.5cm,
  bottom = 2.5cm
}


\setfloatslabelseparator{period}


% Localization
\RequirePackage{polyglossia}
\setdefaultlanguage{russian}
\setotherlanguage{english}


% Use GOST bibliography style in ordinary article too
\bibliographystyle{utf8gost71u}
