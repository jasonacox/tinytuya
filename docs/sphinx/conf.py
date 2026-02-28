# Configuration file for the Sphinx documentation builder.
#
# For the full list of built-in configuration values, see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

from importlib import import_module
from pprint import pformat
from docutils.parsers.rst import Directive
from docutils import nodes
from sphinx import addnodes
from sphinx.util import inspect

# Import from the local working directory
import os
import sys
sys.path.insert(0, os.path.abspath('../..'))
import tinytuya

# -- Project information -----------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#project-information

project = tinytuya.__project__
copyright = tinytuya.__copyright__
author = tinytuya.__author__
release = tinytuya.__version__

# -- General configuration ---------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#general-configuration

# Make the default arg values a but neater.
# Based upon https://stackoverflow.com/a/65195854/6740067
original_object_description = inspect.object_description
def object_description(obj, *args, **kwargs):
    odesc = original_object_description(obj, *args, **kwargs)
    if isinstance(obj, dict) and odesc != 'dict(...)':
        odesc = pformat(obj, indent=4, width=68) #.replace("\n", "<br>\n")
        #print( pf )
    return odesc

inspect.object_description = object_description

# Also make it available to be manually called as `.. pprint:: somevar`
# https://stackoverflow.com/a/59883833/6740067
class PrettyPrintDirective(Directive):
    """Render a constant using pprint.pformat and insert into the document"""
    required_arguments = 1

    def run(self):
        module_path, member_name = self.arguments[0].rsplit('.', 1)
        member_data = getattr(import_module(module_path), member_name)
        code = pformat(member_data, 2, width=68)

        literal = nodes.literal_block(code, code)
        literal['language'] = 'python'

        return [
                addnodes.desc_name(text=member_name),
                addnodes.desc_content('', literal)
        ]

extensions = [
   'sphinx.ext.duration',
   'sphinx.ext.doctest',
   'sphinx.ext.autodoc',
   'sphinx.ext.autosummary',
   'sphinx.ext.napoleon',
]

autosummary_generate = True
autosummary_imported_members = True
toc_object_entries = True

napoleon_numpy_docstring = False


templates_path = ['_templates']
exclude_patterns = ['_build', 'Thumbs.db', '.DS_Store']



# -- Options for HTML output -------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#options-for-html-output

#html_theme = 'alabaster'
html_theme = 'sphinx_rtd_theme'
html_static_path = ['_static']

autosummary_context = {
    'tinytuya_core_autodocument': tinytuya.document.sphinx_autodocument,
    'tinytuya_core_extradocument': tinytuya.document.sphinx_extradocument,
    'tinytuya_parent_modules': [
        {
            'group': 'Standard Device Modules',
            'template': 'autoclass-fake-module.rst',
            'members': [
                { 'name': 'tinytuya.XenonDevice', 'currentmodule': False },
                { 'name': 'tinytuya.Device', 'currentmodule': False },
                { 'name': 'tinytuya.BulbDevice', 'currentmodule': True },
                { 'name': 'tinytuya.OutletDevice', 'currentmodule': True },
                { 'name': 'tinytuya.CoverDevice', 'currentmodule': True },
            ],
        },
        {
            'group': 'Module Functions',
            'template': 'automodule-tinytuya.rst',
            'members': [
                { 'name': 'tinytuya' },
            ],
        }
    ]
}

#autosummary_skip_modules = ([ 'tinytuya.core.'+k for k in tinytuya.document.sphinx_autodocument.keys() ] +
#autosummary_skip_modules = ([ k.split('.')[-1] for k in autosummary_context['tinytuya_parent_modules'].keys() ] +
#                            ['Cloud'])
autosummary_skip_modules = ['tinytuya.Cloud']
for grp in autosummary_context['tinytuya_parent_modules']:
    for gmemb in grp['members']:
        autosummary_skip_modules.append( gmemb['name'] )

#print(autosummary_skip_modules)

def autodoc_skip_member_callback(app, what, name, obj, skip, options):
    #if( what == 'module'):
    #if 'Xenon' in name:
    #    print(what, name, skip, getattr(obj, '__name__', '[no name]'), getattr(obj, '__module__', '[no module]'), obj, options)
    # skip classes that are displayed separately
    if( what == 'module' and getattr(obj, '__module__', '') in autosummary_skip_modules ):
        #print('Skipping:', name, skip, obj)
        return True  # Skip it
    return None  # Use default skipping behavior otherwise

def setup(app):
    app.connect( 'autodoc-skip-member', autodoc_skip_member_callback )
    app.add_directive( 'pprint', PrettyPrintDirective )
