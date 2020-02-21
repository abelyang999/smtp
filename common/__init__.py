image: "python:3.7"

before_script:
  - python - -version
  - pip install - r requirements.txt

test:
  stage: Test
  script:
  - echo "Here I am!"
