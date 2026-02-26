TinyTuya Local API
=====================

{% for grp in tinytuya_parent_modules %}
.. rubric:: {{ grp['group'] }}

.. autosummary::
   :toctree: localapigen{{ loop.index }}
   :template: {{ grp['template'] }}
   :signatures: short
   {% for memb in grp['members'] %}
   {{ memb.name }}
   {%- endfor %}
{% endfor %}
