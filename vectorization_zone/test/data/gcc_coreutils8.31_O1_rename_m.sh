#!/bin/bash
for f in ./*; do
  echo "rename ${f}"
  mv "$f" "${CC}_${PRJ}_${OPTIM}_${f[@]:2}"
done

